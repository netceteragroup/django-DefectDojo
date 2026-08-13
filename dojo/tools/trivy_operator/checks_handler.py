from dojo.models import Finding
from dojo.tools.trivy_operator.uniform_vulnid import UniformTrivyVulnID

CHECK_DESCRIPTION_TEMPLATE = """{description}
**Category**: {category}
**Scope**: {scope}
**Details**:
{details}
"""

TRIVY_SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}


class TrivyChecksHandler:
    def handle_checks(self, labels, endpoints, service, checks, test):
        findings = []
        for check in checks:
            check_title = check.get("title")
            check_severity = TRIVY_SEVERITIES[check.get("severity")]
            check_id = check.get("checkID") or "0"
            check_references = ""
            if check_id != "0":
                check_references = (
                    "https://avd.aquasec.com/misconfig/kubernetes/"
                    + check_id.lower()
                )
            check_remediation = check.get("remediation", "")
            check_messages = check.get("messages", [])
            mitigation = check_remediation or None
            if check_messages:
                messages_text = "\n".join(check_messages)
                if mitigation:
                    mitigation += "\n\n" + messages_text
                else:
                    mitigation = messages_text
            title = f"{check_id} - {check_title}"

            details = ""
            for message in check.get("messages"):
                details += f"{message}\n"

            scope = "undefined"
            if check.get("scope"):
                scope_type = check.get("scope").get("type")
                scope_value = check.get("scope").get("value")
                scope = f"{scope_type} {scope_value}"

            description = CHECK_DESCRIPTION_TEMPLATE.format(
                category=check.get("category"),
                description=check.get("description"),
                details=details,
                scope=scope
            )

            finding = Finding(
                test=test,
                title=title,
                severity=check_severity,
                mitigation=mitigation,
                references=check_references,
                description=description,
                static_finding=True,
                # Findings carry endpoints (affected Kubernetes resources), so they must stay
                # dynamic: the reimporter only mitigates/reactivates endpoints of findings
                # flagged as dynamic_finding.
                dynamic_finding=True,
                service=service,
                fix_available=True,
            )
            if check_id != "0":
                finding.unsaved_vulnerability_ids = [UniformTrivyVulnID().return_uniformed_vulnid(check_id)]
            finding.unsaved_endpoints += endpoints
            findings.append(finding)
        return findings
