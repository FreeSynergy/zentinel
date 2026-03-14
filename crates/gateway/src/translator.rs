//! Translates Gateway API resources into Zentinel `Config`.
//!
//! This is the core mapping layer: it reads all Gateways and HTTPRoutes
//! from the cluster and produces a complete `zentinel_config::Config` that
//! the proxy can hot-reload via `ArcSwap`.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use gateway_api::gatewayclasses::GatewayClass;
use gateway_api::gateways::Gateway;
use gateway_api::httproutes::{
    HTTPRoute, HTTPRouteRulesBackendRefs, HTTPRouteRulesFilters, HTTPRouteRulesFiltersType,
    HTTPRouteRulesMatches, HTTPRouteRulesMatchesPathType,
};
use kube::api::ListParams;
use kube::{Api, Client, ResourceExt};
use tracing::{debug, info, warn};

use zentinel_common::types::{LoadBalancingAlgorithm, Priority};
use zentinel_config::{
    Config, ConnectionPoolConfig, HeaderModifications, HttpVersionConfig, ListenerConfig,
    ListenerProtocol, MatchCondition, RouteConfig, RoutePolicies, ServerConfig, ServiceType,
    UpstreamConfig, UpstreamTarget, UpstreamTimeouts,
};

use crate::error::GatewayError;
use crate::reconcilers::gateway_class::CONTROLLER_NAME;
use crate::reconcilers::ReferenceGrantIndex;

/// Translates Gateway API resources into Zentinel configuration.
///
/// Maintains a shared `ArcSwap<Config>` that the proxy data plane reads
/// from. Each call to `rebuild` reads the full cluster state and atomically
/// swaps the config.
pub struct ConfigTranslator {
    config: Arc<ArcSwap<Config>>,
    reference_grants: Arc<ReferenceGrantIndex>,
}

impl ConfigTranslator {
    pub fn new(
        config: Arc<ArcSwap<Config>>,
        reference_grants: Arc<ReferenceGrantIndex>,
    ) -> Self {
        Self {
            config,
            reference_grants,
        }
    }

    /// Get the current config (for reading).
    pub fn current_config(&self) -> Arc<Config> {
        self.config.load_full()
    }

    /// Rebuild the full Zentinel config from cluster state.
    ///
    /// Reads all Gateway and HTTPRoute resources, filters to those owned
    /// by our GatewayClass, and translates them into a `Config`.
    pub async fn rebuild(&self, client: &Client) -> Result<(), GatewayError> {
        // List all GatewayClasses to find ours
        let gc_api: Api<GatewayClass> = Api::all(client.clone());
        let gateway_classes = gc_api.list(&ListParams::default()).await?;

        let our_classes: Vec<String> = gateway_classes
            .items
            .iter()
            .filter(|gc: &&GatewayClass| gc.spec.controller_name == CONTROLLER_NAME)
            .map(|gc: &GatewayClass| gc.name_any())
            .collect();

        if our_classes.is_empty() {
            debug!("No GatewayClasses owned by us");
            return Ok(());
        }

        // List all Gateways
        let gw_api: Api<Gateway> = Api::all(client.clone());
        let all_gateways = gw_api.list(&ListParams::default()).await?;

        let our_gateways: Vec<&Gateway> = all_gateways
            .items
            .iter()
            .filter(|gw: &&Gateway| our_classes.contains(&gw.spec.gateway_class_name))
            .collect();

        // List all HTTPRoutes
        let route_api: Api<HTTPRoute> = Api::all(client.clone());
        let all_routes = route_api.list(&ListParams::default()).await?;

        // Build config
        let mut listeners = Vec::new();
        let mut routes = Vec::new();
        let mut upstreams = HashMap::new();

        // Translate Gateways → Listeners
        for gw in &our_gateways {
            let gw_listeners = self.translate_gateway(gw);
            listeners.extend(gw_listeners);
        }

        // Translate HTTPRoutes → Routes + Upstreams
        for route in &all_routes.items {
            // Check if any parent ref points to one of our Gateways
            let parent_refs = route.spec.parent_refs.as_ref();
            let is_ours = parent_refs.is_some_and(|refs: &Vec<gateway_api::httproutes::HTTPRouteParentRefs>| {
                refs.iter().any(|pr: &gateway_api::httproutes::HTTPRouteParentRefs| {
                    let gw_ns = pr
                        .namespace
                        .as_deref()
                        .unwrap_or("default");
                    let gw_name = pr.name.as_str();
                    our_gateways.iter().any(|g: &&Gateway| {
                        g.name_any() == gw_name
                            && g.namespace().unwrap_or_default() == gw_ns
                    })
                })
            });

            if !is_ours {
                continue;
            }

            let (route_configs, upstream_configs) = self.translate_httproute(route)?;
            routes.extend(route_configs);
            upstreams.extend(upstream_configs);
        }

        if listeners.is_empty() {
            debug!("No listeners produced, keeping existing config");
            return Ok(());
        }

        let new_config = Config {
            schema_version: zentinel_config::CURRENT_SCHEMA_VERSION.to_string(),
            server: ServerConfig {
                worker_threads: 0, // auto-detect
                max_connections: 10000,
                graceful_shutdown_timeout_secs: 30,
                daemon: false,
                pid_file: None,
                user: None,
                group: None,
                working_directory: None,
                trace_id_format: Default::default(),
                auto_reload: false,
            },
            listeners,
            routes,
            upstreams,
            filters: HashMap::new(),
            agents: vec![],
            waf: None,
            namespaces: vec![],
            limits: Default::default(),
            observability: Default::default(),
            rate_limits: Default::default(),
            cache: None,
            default_upstream: None,
        };

        info!(
            listeners = new_config.listeners.len(),
            routes = new_config.routes.len(),
            upstreams = new_config.upstreams.len(),
            "Config rebuilt from Gateway API resources"
        );

        self.config.store(Arc::new(new_config));
        Ok(())
    }

    /// Translate a Gateway into Zentinel listener configs.
    fn translate_gateway(&self, gateway: &Gateway) -> Vec<ListenerConfig> {
        let gw_name = gateway.name_any();
        let gw_ns = gateway.namespace().unwrap_or_default();

        gateway
            .spec
            .listeners
            .iter()
            .map(|listener| {
                let id = format!("{gw_ns}-{gw_name}-{}", listener.name);
                let port = listener.port;
                let protocol = match listener.protocol.as_str() {
                    "HTTPS" => ListenerProtocol::Https,
                    _ => ListenerProtocol::Http,
                };

                ListenerConfig {
                    id,
                    address: format!("0.0.0.0:{port}"),
                    protocol,
                    tls: None, // TODO: translate from Gateway TLS config + Secrets
                    default_route: None,
                    request_timeout_secs: 60,
                    keepalive_timeout_secs: 75,
                    max_concurrent_streams: 100,
                    keepalive_max_requests: None,
                }
            })
            .collect()
    }

    /// Translate an HTTPRoute into Zentinel route and upstream configs.
    fn translate_httproute(
        &self,
        route: &HTTPRoute,
    ) -> Result<(Vec<RouteConfig>, HashMap<String, UpstreamConfig>), GatewayError> {
        let route_name = route.name_any();
        let route_ns = route.namespace().unwrap_or_else(|| "default".into());

        let rules = route.spec.rules.as_ref().cloned().unwrap_or_default();
        let mut route_configs = Vec::new();
        let mut upstream_configs = HashMap::new();

        // Hostnames from the route spec
        let hostnames: Vec<String> = route
            .spec
            .hostnames
            .clone()
            .unwrap_or_default();

        for (rule_idx, rule) in rules.iter().enumerate() {
            let rule_id = format!("{route_ns}-{route_name}-rule{rule_idx}");

            // Build match conditions from rule matches
            let matches = self.translate_matches(&rule.matches, &hostnames[..]);

            // Build upstream from backend refs
            let (upstream_id, upstream) =
                self.translate_backends(&rule_id, &rule.backend_refs, &route_ns)?;

            if let Some(upstream) = upstream {
                upstream_configs.insert(upstream_id.clone(), upstream);
            }

            // Build header modifications from filters
            let request_headers = self.extract_request_header_mods(&rule.filters);
            let response_headers = self.extract_response_header_mods(&rule.filters);

            let route_config = RouteConfig {
                id: rule_id,
                priority: Priority::Normal,
                matches,
                upstream: Some(upstream_id),
                service_type: ServiceType::Web,
                policies: RoutePolicies {
                    request_headers,
                    response_headers,
                    ..RoutePolicies::default()
                },
                filters: vec![],
                builtin_handler: None,
                waf_enabled: false,
                circuit_breaker: None,
                retry_policy: None,
                static_files: None,
                api_schema: None,
                inference: None,
                error_pages: None,
                websocket: false,
                websocket_inspection: false,
                shadow: None,
                fallback: None,
            };

            route_configs.push(route_config);
        }

        Ok((route_configs, upstream_configs))
    }

    /// Translate HTTPRoute matches into Zentinel match conditions.
    fn translate_matches(
        &self,
        rule_matches: &Option<Vec<HTTPRouteRulesMatches>>,
        hostnames: &[String],
    ) -> Vec<MatchCondition> {
        let mut conditions = Vec::new();

        // Add host matches
        for hostname in hostnames {
            conditions.push(MatchCondition::Host(hostname.clone()));
        }

        let route_matches = match rule_matches {
            Some(m) => m,
            None => {
                // No matches = match everything (path prefix "/")
                if conditions.is_empty() {
                    conditions.push(MatchCondition::PathPrefix("/".to_string()));
                }
                return conditions;
            }
        };

        if route_matches.is_empty() && conditions.is_empty() {
            conditions.push(MatchCondition::PathPrefix("/".to_string()));
            return conditions;
        }

        for m in route_matches {
            // Path match
            if let Some(ref path) = m.path {
                let value = path.value.as_deref().unwrap_or("/").to_string();

                match path.r#type {
                    Some(HTTPRouteRulesMatchesPathType::Exact) => {
                        conditions.push(MatchCondition::Path(value));
                    }
                    Some(HTTPRouteRulesMatchesPathType::RegularExpression) => {
                        conditions.push(MatchCondition::PathRegex(value));
                    }
                    _ => {
                        conditions.push(MatchCondition::PathPrefix(value));
                    }
                }
            }

            // Header matches
            if let Some(ref headers) = m.headers {
                for header in headers {
                    conditions.push(MatchCondition::Header {
                        name: header.name.clone(),
                        value: Some(header.value.clone()),
                    });
                }
            }

            // Method match
            if let Some(ref method) = m.method {
                // HTTPRouteRulesMatchesMethod is an enum with variants like Get, Post, etc.
                let method_str = serde_json::to_value(method)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| format!("{method:?}"));
                conditions.push(MatchCondition::Method(vec![method_str]));
            }

            // Query parameter matches
            if let Some(ref params) = m.query_params {
                for param in params {
                    conditions.push(MatchCondition::QueryParam {
                        name: param.name.clone(),
                        value: Some(param.value.clone()),
                    });
                }
            }
        }

        // If only host matches and no path, add a catch-all prefix
        if conditions.iter().all(|c| matches!(c, MatchCondition::Host(_))) && !conditions.is_empty()
        {
            conditions.push(MatchCondition::PathPrefix("/".to_string()));
        }

        conditions
    }

    /// Translate HTTPRoute backend references into a Zentinel upstream.
    fn translate_backends(
        &self,
        rule_id: &str,
        backend_refs: &Option<Vec<HTTPRouteRulesBackendRefs>>,
        route_ns: &str,
    ) -> Result<(String, Option<UpstreamConfig>), GatewayError> {
        let upstream_id = format!("{rule_id}-upstream");

        let backend_refs = match backend_refs {
            Some(refs) => refs,
            None => return Ok((upstream_id, None)),
        };

        if backend_refs.is_empty() {
            return Ok((upstream_id, None));
        }

        let mut targets = Vec::new();

        for backend in backend_refs {
            let svc_name = &backend.name;
            let svc_ns = backend
                .namespace
                .as_deref()
                .unwrap_or(route_ns);
            let svc_port = backend.port.unwrap_or(80);
            let weight = backend.weight.unwrap_or(1);

            // Check cross-namespace reference permission
            if svc_ns != route_ns
                && !self.reference_grants.is_permitted(
                    route_ns,
                    "HTTPRoute",
                    svc_ns,
                    "Service",
                    svc_name,
                )
            {
                warn!(
                    route_ns = route_ns,
                    service = %svc_name,
                    service_ns = %svc_ns,
                    "Cross-namespace backend reference denied"
                );
                continue;
            }

            // Use Kubernetes DNS for service discovery:
            // <service>.<namespace>.svc.cluster.local:<port>
            let address = format!("{svc_name}.{svc_ns}.svc.cluster.local:{svc_port}");

            targets.push(UpstreamTarget {
                address,
                weight: weight as u32,
                max_requests: None,
                metadata: HashMap::from([
                    ("k8s-service".to_string(), svc_name.clone()),
                    ("k8s-namespace".to_string(), svc_ns.to_string()),
                ]),
            });
        }

        if targets.is_empty() {
            return Err(GatewayError::Translation(format!(
                "Rule '{rule_id}' has no valid backend references"
            )));
        }

        let upstream = UpstreamConfig {
            id: upstream_id.clone(),
            targets,
            load_balancing: LoadBalancingAlgorithm::RoundRobin,
            sticky_session: None,
            health_check: None,
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig::default(),
        };

        Ok((upstream_id, Some(upstream)))
    }

    /// Extract request header modifications from HTTPRoute filters.
    fn extract_request_header_mods(
        &self,
        filters: &Option<Vec<HTTPRouteRulesFilters>>,
    ) -> HeaderModifications {
        let mut mods = HeaderModifications::default();

        let filters = match filters {
            Some(f) => f,
            None => return mods,
        };

        for filter in filters {
            if filter.r#type == HTTPRouteRulesFiltersType::RequestHeaderModifier {
                if let Some(ref modifier) = filter.request_header_modifier {
                    if let Some(ref adds) = modifier.add {
                        for header in adds {
                            mods.add
                                .insert(header.name.clone(), header.value.clone());
                        }
                    }
                    if let Some(ref removes) = modifier.remove {
                        mods.remove.extend(removes.clone());
                    }
                    if let Some(ref sets) = modifier.set {
                        for header in sets {
                            mods.set
                                .insert(header.name.clone(), header.value.clone());
                        }
                    }
                }
            }
        }

        mods
    }

    /// Extract response header modifications from HTTPRoute filters.
    fn extract_response_header_mods(
        &self,
        filters: &Option<Vec<HTTPRouteRulesFilters>>,
    ) -> HeaderModifications {
        let mut mods = HeaderModifications::default();

        let filters = match filters {
            Some(f) => f,
            None => return mods,
        };

        for filter in filters {
            if filter.r#type == HTTPRouteRulesFiltersType::ResponseHeaderModifier {
                if let Some(ref modifier) = filter.response_header_modifier {
                    if let Some(ref adds) = modifier.add {
                        for header in adds {
                            mods.add
                                .insert(header.name.clone(), header.value.clone());
                        }
                    }
                    if let Some(ref removes) = modifier.remove {
                        mods.remove.extend(removes.clone());
                    }
                    if let Some(ref sets) = modifier.set {
                        for header in sets {
                            mods.set
                                .insert(header.name.clone(), header.value.clone());
                        }
                    }
                }
            }
        }

        mods
    }
}
