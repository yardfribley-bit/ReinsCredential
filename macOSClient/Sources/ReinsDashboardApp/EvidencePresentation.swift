import EvidenceCore

/// User-facing explanations preserve the backend's observation strength.
/// They never promote a descriptor or socket observation into a proven upload.
extension EvidenceRecord {
    var findingTitle: String {
        switch sourceType {
        case "agent_discovered": return L10n.tr("finding.agent")
        case "process_discovered": return L10n.tr("finding.process")
        case "agent_changed", "process_changed": return L10n.tr("finding.changed")
        case "agent_no_longer_observed", "process_no_longer_observed": return L10n.tr("finding.gone")
        case "filesystem_change": return L10n.tr("finding.fs")
        case "sensitive_network_cooccurrence": return L10n.tr("finding.cooccur")
        case "activity_observed":
            return targetResource.isEmpty ? L10n.tr("finding.activity") : L10n.tr("finding.held")
        case "sensitive_access_observed":
            return evidenceBasis == "inferred" ? L10n.tr("finding.inferred") : L10n.tr("finding.accessTime")
        case "sensor_gap": return L10n.tr("finding.gap")
        case "fatal_error", "gateway_fatal": return L10n.tr("finding.fatal")
        case "coverage": return L10n.tr("finding.health")
        case "shutdown_summary": return L10n.tr("finding.shutdown")
        case "sensitive_payload_observed": return L10n.tr("finding.payload")
        case "payload_observed": return L10n.tr("finding.gatewayIn")
        case "sensitive_content_delivery_attempt": return L10n.tr("finding.deliveryPrep")
        case "sensitive_content_delivered": return L10n.tr("finding.delivered")
        case "transfer_result": return L10n.tr("finding.gatewayResult")
        case "egress_transfer": return L10n.tr("finding.egress")
        case "sensitive_access_closed": return L10n.tr("finding.closed")
        case "egress_channel_unseen": return L10n.tr("finding.unseen")
        case "egress_proxy_ready": return L10n.tr("finding.proxyReady")
        case "egress_proxy_stopped": return L10n.tr("finding.proxyStopped")
        case "gateway_request_failed": return L10n.tr("finding.requestFailed")
        case "gateway_ready": return L10n.tr("finding.gatewayReady")
        default: return actionType
        }
    }

    var recommendedAction: String? {
        switch sourceType {
        case "activity_observed" where !targetResource.isEmpty:
            return L10n.tr("action.held")
        case "sensitive_access_observed" where evidenceBasis == "inferred":
            return L10n.tr("action.inferred")
        case "sensitive_access_observed":
            return L10n.tr("action.accessTime")
        case "sensitive_network_cooccurrence":
            return L10n.tr("action.cooccur")
        case "filesystem_change":
            return L10n.tr("action.fs")
        case "sensor_gap":
            return L10n.tr("action.gap")
        case "fatal_error", "gateway_fatal":
            return L10n.tr("action.fatal")
        case "sensitive_payload_observed":
            return L10n.tr("action.payload")
        case "transfer_result", "egress_transfer":
            return L10n.tr("action.transfer")
        case "sensitive_access_closed" where uploadVerdict == "uploaded":
            return L10n.tr("action.uploaded")
        case "sensitive_access_closed" where uploadVerdict == "attempted":
            return L10n.tr("action.attempted")
        case "sensitive_access_closed" where uploadVerdict == "not_found":
            return L10n.tr("action.notFound")
        case "sensitive_access_closed" where uploadVerdict == "not_visible":
            return L10n.tr("action.notVisible")
        case "egress_channel_unseen":
            return L10n.tr("action.unseen")
        default: return nil
        }
    }
}
