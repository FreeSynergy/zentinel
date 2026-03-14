//! Gateway reconciler.
//!
//! Watches Gateway resources and translates them into Zentinel listener
//! configurations. Updates Gateway status with addresses and conditions.

use gateway_api::gatewayclasses::GatewayClass;
use gateway_api::gateways::Gateway;
use gateway_api::httproutes::HTTPRoute;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::gateway_class::CONTROLLER_NAME;
use crate::error::GatewayError;

/// Reconciler for Gateway resources.
pub struct GatewayReconciler {
    client: Client,
}

impl GatewayReconciler {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Reconcile a Gateway resource.
    ///
    /// Verifies the Gateway references a GatewayClass we own, then
    /// translates listeners and updates status.
    pub async fn reconcile(
        &self,
        gateway: Arc<Gateway>,
    ) -> Result<Action, GatewayError> {
        let name = gateway.name_any();
        let namespace = gateway.namespace().unwrap_or_else(|| "default".into());
        let class_name = &gateway.spec.gateway_class_name;

        // Check if the referenced GatewayClass belongs to us
        if !self.is_our_gateway_class(class_name).await? {
            debug!(
                name = %name,
                namespace = %namespace,
                class = %class_name,
                "Ignoring Gateway for unowned GatewayClass"
            );
            return Ok(Action::await_change());
        }

        let generation = gateway.metadata.generation.unwrap_or(0);

        // Note: we do NOT skip based on generation alone here because
        // attached route counts can change without the Gateway's generation
        // changing (HTTPRoutes are separate resources). We always recompute
        // status but use a requeue interval to avoid tight loops.

        info!(
            name = %name,
            namespace = %namespace,
            listeners = gateway.spec.listeners.len(),
            generation,
            "Reconciling Gateway"
        );

        // Update Gateway status with listener info and attached route counts
        self.update_status(&gateway, &namespace).await?;

        // Requeue periodically to pick up changes in attached route counts
        // (HTTPRoutes are separate resources, their changes don't trigger
        // Gateway reconciliation directly)
        Ok(Action::requeue(std::time::Duration::from_secs(10)))
    }

    /// Check if a GatewayClass name belongs to our controller.
    async fn is_our_gateway_class(&self, class_name: &str) -> Result<bool, GatewayError> {
        let api: Api<GatewayClass> = Api::all(self.client.clone());
        match api.get(class_name).await {
            Ok(gc) => Ok(gc.spec.controller_name == CONTROLLER_NAME),
            Err(kube::Error::Api(err)) if err.code == 404 => {
                debug!(class = %class_name, "GatewayClass not found");
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Count attached HTTPRoutes per listener for this Gateway.
    async fn count_attached_routes(
        &self,
        gw_name: &str,
        gw_namespace: &str,
    ) -> Result<std::collections::HashMap<String, i32>, GatewayError> {
        let route_api: Api<HTTPRoute> = Api::all(self.client.clone());
        let routes = route_api.list(&ListParams::default()).await?;

        let mut counts: std::collections::HashMap<String, i32> =
            std::collections::HashMap::new();

        for route in &routes.items {
            let parent_refs = route.spec.parent_refs.as_ref();
            if let Some(refs) = parent_refs {
                for pr in refs {
                    let route_ns = route.namespace().unwrap_or_default();
                    let pr_ns = pr.namespace.as_deref().unwrap_or(&route_ns);
                    if pr.name == gw_name && pr_ns == gw_namespace {
                        // If sectionName is specified, count for that listener
                        // Otherwise, count for all listeners
                        if let Some(ref section) = pr.section_name {
                            *counts.entry(section.clone()).or_insert(0) += 1;
                        } else {
                            // Attach to all listeners (use empty string as wildcard key)
                            *counts.entry(String::new()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        Ok(counts)
    }

    /// Update Gateway status conditions and addresses.
    async fn update_status(
        &self,
        gateway: &Gateway,
        namespace: &str,
    ) -> Result<(), GatewayError> {
        let name = gateway.name_any();
        let generation = gateway.metadata.generation.unwrap_or(0);
        let now = chrono::Utc::now().to_rfc3339();

        // Count attached routes per listener
        let attached_counts = self.count_attached_routes(&name, namespace).await?;
        let wildcard_count = attached_counts.get("").copied().unwrap_or(0);

        // Build listener statuses
        let listener_statuses: Vec<serde_json::Value> = gateway
            .spec
            .listeners
            .iter()
            .map(|l| {
                let listener_count = attached_counts
                    .get(&l.name)
                    .copied()
                    .unwrap_or(0)
                    + wildcard_count;

                json!({
                    "name": l.name,
                    "attachedRoutes": listener_count,
                    "supportedKinds": supported_route_kinds(&l.protocol),
                    "conditions": [{
                        "type": "Accepted",
                        "status": "True",
                        "reason": "Accepted",
                        "message": "Listener accepted",
                        "observedGeneration": generation,
                        "lastTransitionTime": now,
                    }, {
                        "type": "Programmed",
                        "status": "True",
                        "reason": "Programmed",
                        "message": "Listener programmed in Zentinel",
                        "observedGeneration": generation,
                        "lastTransitionTime": now,
                    }, {
                        "type": "ResolvedRefs",
                        "status": "True",
                        "reason": "ResolvedRefs",
                        "message": "All references resolved",
                        "observedGeneration": generation,
                        "lastTransitionTime": now,
                    }]
                })
            })
            .collect();

        let status = json!({
            "status": {
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "reason": "Accepted",
                    "message": "Gateway accepted by Zentinel controller",
                    "observedGeneration": generation,
                    "lastTransitionTime": now,
                }, {
                    "type": "Programmed",
                    "status": "True",
                    "reason": "Programmed",
                    "message": "Gateway programmed, listeners active",
                    "observedGeneration": generation,
                    "lastTransitionTime": now,
                }],
                "listeners": listener_statuses,
            }
        });

        let api: Api<Gateway> = Api::namespaced(self.client.clone(), namespace);
        api.patch_status(
            &name,
            &PatchParams::apply(CONTROLLER_NAME),
            &Patch::Merge(&status),
        )
        .await?;

        Ok(())
    }

    /// Handle errors during reconciliation.
    pub fn error_policy(
        _obj: Arc<Gateway>,
        error: &GatewayError,
        _ctx: Arc<()>,
    ) -> Action {
        warn!(error = %error, "Gateway reconciliation failed");
        Action::requeue(std::time::Duration::from_secs(30))
    }
}

/// Return the supported route kinds for a given listener protocol.
fn supported_route_kinds(protocol: &str) -> Vec<serde_json::Value> {
    match protocol {
        "HTTP" | "HTTPS" => vec![
            json!({"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}),
        ],
        "TLS" => vec![
            json!({"group": "gateway.networking.k8s.io", "kind": "TLSRoute"}),
        ],
        _ => vec![
            json!({"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}),
        ],
    }
}
