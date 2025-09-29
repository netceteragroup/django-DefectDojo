import datetime

from dojo.models import Finding


class Health:
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
        description = "This is a Health Finding \n" + finding.get("Description", "") + "\n"
        description += f"**AWS Finding ARN:** {finding_id}\n"
        description += f"**Resource IDs:** {', '.join(set(resource_arns))}\n"
        description += f"**AwsAccountId:** {finding.get('AwsAccountId', '')}\n"
        if finding.get("Region"):
            description += f"**Region:** {finding.get('Region', '')}\n"
        description += f"**Generator ID:** {finding.get('GeneratorId', '')}\n"
        title_suffix = ""
        for resource in finding.get("Resources", []):
            component_name = resource.get("Type")
            resource_id = resource["Id"].split(":")[-1]
            impact.append(f"Resource: {resource_id}")
            title_suffix = f" - Resource: {resource_id}"
        references.append((finding.get("SourceUrl", "") or ""))
        false_p = False
        result = Finding(
            title=f"{title}{title_suffix}",
            test=test,
            description=description,
            references="\n".join(references),
            severity=severity,
            impact="\n".join(impact),
            verified=False,
            false_p=false_p,
            unique_id_from_tool=finding_id,
            static_finding=True,
            dynamic_finding=False,
            component_name=component_name,
        )
        if epss_score is not None:
            result.epss_score = epss_score
        # Add the unsaved vulnerability ids
        result.unsaved_vulnerability_ids = unsaved_vulnerability_ids
        return result
