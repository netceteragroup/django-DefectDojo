from dojo.models import Finding


class IamAccessAnalyzer:
    def get_item(self, finding: dict, test):
        finding_id = finding.get("Id", "")
        title = finding.get("Title", "")
        severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL").title()
        resource_arns = [arn for resource in finding.get("Resources", [])
                         if (arn := resource.get("Id"))]
        impact = []
        references = []
        unsaved_vulnerability_ids = []
        epss_score = None
        mitigation = finding.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
        mitigation += "\n" + (finding.get("Remediation", {}).get("Recommendation", {}).get("Url", "") or "")
        description = "This is an IAM Access Analyzer Finding \n" + finding.get("Description", "") + "\n"
        description += f"**AWS Finding ARN:** {finding_id}\n"
        description += f"**Resource IDs:** {', '.join(set(resource_arns))}\n"
        description += f"**AwsAccountId:** {finding.get('AwsAccountId', '')}\n"
        if finding.get("Region"):
            description += f"**Region:** {finding.get('Region', '')}\n"
        description += f"**Generator ID:** {finding.get('GeneratorId', '')}\n"
        title_suffix = ""
        for resource in finding.get("Resources", []):
            resource_id = resource["Id"].split(":")[-1]
            impact.append(f"Resource: {resource_id}")
            title_suffix = f" - Resource: {resource_id}"
        if remediation_rec_url := finding.get("Remediation", {}).get("Recommendation", {}).get("Url"):
            references.append(remediation_rec_url)
        result = Finding(
            title=f"{title}{title_suffix}",
            test=test,
            description=description,
            mitigation=mitigation,
            references="\n".join(references),
            severity=severity,
            impact="\n".join(impact),
            active=True,
            verified=False,
            false_p=False,
            unique_id_from_tool=finding_id,
            is_mitigated=False,
            static_finding=True,
            dynamic_finding=False,
        )
        if epss_score is not None:
            result.epss_score = epss_score
        # Add the unsaved vulnerability ids
        result.unsaved_vulnerability_ids = unsaved_vulnerability_ids
        return result
