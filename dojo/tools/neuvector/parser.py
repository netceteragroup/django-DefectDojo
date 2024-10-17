import json
import logging

from datetime import datetime

from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)

NEUVECTOR_SCAN_NAME = "NeuVector (REST)"
NEUVECTOR_IMAGE_SCAN_ENGAGEMENT_NAME = "NV image scan"
NEUVECTOR_CONTAINER_SCAN_ENGAGEMENT_NAME = "NV container scan"


class NeuVectorJsonParser:
    def parse(self, json_output, test):
        tree = self.parse_json(json_output)
        items = []
        if tree:
            items = list(self.get_items(tree, test))
        return items

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, "utf-8"))
            except Exception:
                tree = json.loads(data)
        except Exception:
            msg = "Invalid format"
            raise ValueError(msg)

        return tree

    def get_items(self, tree, test):
        items = {}
        # old-style report with vulnerabilities of an endpoint
        if "report" in tree:
            vulnerabilityTree = tree.get("report").get("vulnerabilities", [])
            for node in vulnerabilityTree:
                item = get_item(node, test)
                package_name = node.get("package_name")
                if len(package_name) > 64:
                    package_name = package_name[-64:]
                unique_key = node.get("name") + str(
                    package_name
                    + str(node.get("package_version"))
                    + str(node.get("severity")),
                )
                items[unique_key] = item
        # asset-style collection with vulnerabilities of several assets
        if "vulnerabilities" in tree:
            vulnerabilityTree = tree.get("vulnerabilities", [])
            for node in vulnerabilityTree:
                item = get_asset_item(node, test)
                unique_key = node.get("name") + str(node.get("severity"))
                items[unique_key] = item
        return list(items.values())


def get_item(vulnerability, test):
    severity = (
        convert_severity(vulnerability.get("severity"))
        if "severity" in vulnerability
        else "Info"
    )
    vector = (
        vulnerability.get("vectors_v3")
        if "vectors_v3" in vulnerability
        else "CVSSv3 vector not provided. "
    )
    fixed_version = (
        vulnerability.get("fixed_version")
        if "fixed_version" in vulnerability
        else "There seems to be no fix yet. Please check description field."
    )
    score_v3 = (
        vulnerability.get("score_v3")
        if "score_v3" in vulnerability
        else "No CVSSv3 score yet."
    )
    package_name = vulnerability.get("package_name")
    if len(package_name) > 64:
        package_name = package_name[-64:]
    description = (
        vulnerability.get("description")
        if "description" in vulnerability
        else ""
    )
    link = vulnerability.get("link") if "link" in vulnerability else ""

    # create the finding object
    finding = Finding(
        title=vulnerability.get("name")
        + ": "
        + package_name
        + " - "
        + vulnerability.get("package_version"),
        test=test,
        severity=severity,
        description=description
        + "<p> Vulnerable Package: "
        + package_name
        + "</p><p> Current Version: "
        + str(vulnerability["package_version"])
        + "</p>",
        mitigation=fixed_version.title(),
        references=link,
        component_name=package_name,
        component_version=vulnerability.get("package_version"),
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        severity_justification=f"{vector} (CVSS v3 base score: {score_v3})\n",
        impact=severity,
    )
    finding.unsaved_vulnerability_ids = [vulnerability.get("name")]
    finding.description = finding.description.strip()

    return finding


ASSET_FINDING_DESCRIPTION_TEMPLATE = """**Title:** {title}
**Details:**
{description}
**Feed rating:** {feed_rating}
**Published on**: {published_date}
**Reference**: {reference}
**Affected packages:**
{affected packages}
"""


def get_asset_item(vulnerability, test):
    severity = (
        convert_severity(vulnerability.get("severity"))
        if "severity" in vulnerability
        else "Info"
    )

    vulnerability_id = vulnerability.get("name")

    vuln_description = vulnerability.get("description", "").strip()

    published_date = None
    published_ts = vulnerability.get("published_timestamp", 0)
    if published_ts > 0:
        published_date = datetime.fromtimestamp(int(published_ts))

    reference = vulnerability.get("link", "not provided")

    affected_packages = ""

    packages = vulnerability.get("packages", {})
    if len(packages.values()) > 0:
        for package_name, package_versions in packages.items():
            affected_packages += f"*{package_name}*\n"

            for versions in package_versions:
                installed=versions.get("package_version", "unknown")
                fixed=versions.get("fixed_version", "unknown")
                affected_packages += f"  installed version: {installed}\n"
                affected_packages += f"  fixed version: {fixed}\n"

            affected_packages += "\n"

    description = ASSET_FINDING_DESCRIPTION_TEMPLATE.format(
        title=vulnerability_id,
        description=vuln_description,
        feed_rating=vulnerability.get("feed_rating", "not provided"),
        published_date=published_date,
        reference=reference,
        affected_packages=affected_packages,
    )

    # create the finding object
    finding = Finding(
        title=vulnerability_id,
        test=test,
        description=description,
        severity=severity,
        impact="",
        url=reference,
        cvssv3=vulnerability.get("vectors_v3", ""),
        cvssv3_score=vulnerability.get("score_v3", ""),
        publish_date=published_date,
    )

    finding.unsaved_vulnerability_ids = [vulnerability_id]

    finding.unsaved_endpoints = []

    nodes = vulnerability.get("nodes", [])
    for asset in nodes:
        endpoint = endpoint_from_asset("node", asset)
        finding.unsaved_endpoints.append(endpoint)

    workloads = vulnerability.get("workloads", [])
    for asset in workloads:
        endpoint = endpoint_from_asset("workload", asset)
        finding.unsaved_endpoints.append(endpoint)

    images = vulnerability.get("images", [])
    for asset in images:
        endpoint = endpoint_from_asset("image", asset)
        finding.unsaved_endpoints.append(endpoint)

    platforms = vulnerability.get("platforms", [])
    for asset in platforms:
        endpoint = endpoint_from_asset("platform", asset)
        finding.unsaved_endpoints.append(endpoint)

    return finding


def endpoint_from_asset(kind, asset):
    # usually, there is only one namespace (domain, as NeuVector name it)
    namespaces = asset.get("domains", [])

    name = asset.get("display_name", "")

    if kind == "workload":
        service = asset.get("service", "unknown_service")
        image = asset.get("image", "unknown_image")
        name += f"/{service}/{image}"

    endpoint = Endpoint(
        # host needs to comply with domain name syntax, we just expect that
        # there will be only one namespace
        host='-'.join(namespaces),
        # we abuse path to have as much details as possible
        path=f"{kind}/{name}"
    )

    return endpoint

# see neuvector/share/types.go
def convert_severity(severity):
    if severity.lower() == "critical":
        return "Critical"
    if severity.lower() == "high":
        return "High"
    if severity.lower() == "medium":
        return "Medium"
    if severity.lower() == "low":
        return "Low"
    if severity == "":
        return "Info"
    return severity.title()


class NeuVectorParser:
    def get_scan_types(self):
        return [NEUVECTOR_SCAN_NAME]

    def get_label_for_scan_types(self, scan_type):
        return NEUVECTOR_SCAN_NAME

    def get_description_for_scan_types(self, scan_type):
        return "JSON output of /v1/scan/{entity}/{id} endpoint (vulnerabilities of an endpoint). Or vulnerabilities of several assets (VulnerabilityAsset / ComplianceAsset)."

    def get_findings(self, filename, test):
        if filename is None:
            return []

        if filename.name.lower().endswith(".json"):
            return NeuVectorJsonParser().parse(filename, test)
        msg = "Unknown File Format"
        raise ValueError(msg)
