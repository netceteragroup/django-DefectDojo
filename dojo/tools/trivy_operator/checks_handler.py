from dojo.models import Finding

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
    def handle_checks(self, endpoint, service, checks, test):
        findings = []
        for check in checks:
            check_title = check.get("title")
            check_severity = TRIVY_SEVERITIES[check.get("severity")]
            check_id = check.get("checkID", "0")
            check_references = ""
            if check_id != 0:
                check_references = (
                    "https://avd.aquasec.com/misconfig/kubernetes/"
                    + check_id.lower()
                )
            title = f"{check_id} - {check_title}"
            mitigation = check.get("remediation")

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
                references=check_references,
                description=description,
                static_finding=True,
                dynamic_finding=False,
                service=service,
                mitigation=mitigation,
            )
            if check_id:
                finding.unsaved_vulnerability_ids = [check_id]
            finding.unsaved_endpoints.append(endpoint)
            findings.append(finding)
        return findings
