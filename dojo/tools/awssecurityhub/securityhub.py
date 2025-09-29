import datetime

from dojo.models import Finding


class SecurityHub:
    def get_item(self, finding: dict, test):
        finding_id = finding.get("Id", "")
        title = finding.get("Title", "")
        severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL").title()
        mitigation = ""
        impact = []
        references = []
        unsaved_vulnerability_ids = []
        epss_score = None
        mitigations = finding.get("FindingProviderFields", {}).get("Types")
        for mitigate in mitigations:
            mitigation += mitigate + "\n"
        active = True
        if finding.get("RecordState") == "ACTIVE":
            is_Mitigated = False
            mitigated = None
        else:
            is_Mitigated = True
            if finding.get("LastObservedAt"):
                try:
                    mitigated = datetime.datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%S.%fZ")
                except Exception:
                    mitigated = datetime.datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%fZ")
            else:
                mitigated = datetime.datetime.now(datetime.UTC)
        description = f"This is a Security Hub Finding\n{finding.get('Description', '')}" + "\n"
        description += f"**AWS Finding ARN:** {finding_id}\n"
        description += f"**AwsAccountId:** {finding.get('AwsAccountId', '')}\n"
        description += f"**Region:** {finding.get('Region', '')}\n"
        description += f"**Generator ID:** {finding.get('GeneratorId', '')}\n"
        title_suffix = ""
        hosts = []
        for resource in finding.get("Resources", []):
            component_name = resource.get("Type")
            resource_id = resource["Id"].split(":")[-1]
            impact.append(f"Resource: {resource_id}")
            title_suffix = f" - Resource: {resource_id}"
        if remediation_rec_url := finding.get("Remediation", {}).get("Recommendation", {}).get("Url"):
            references.append(remediation_rec_url)
        false_p = False
        result = Finding(
            title=f"{title}{title_suffix}",
            test=test,
            description=description,
            mitigation=mitigation,
            references="\n".join(references),
            severity=severity,
            impact="\n".join(impact),
            active=active,
            verified=False,
            false_p=false_p,
            unique_id_from_tool=finding_id,
            mitigated=mitigated,
            is_mitigated=is_Mitigated,
            static_finding=True,
            dynamic_finding=False,
            component_name=component_name,
        )
        result.unsaved_endpoints = []
        result.unsaved_endpoints.extend(hosts)
        if epss_score is not None:
            result.epss_score = epss_score
        # Add the unsaved vulnerability ids
        result.unsaved_vulnerability_ids = unsaved_vulnerability_ids
        return result
