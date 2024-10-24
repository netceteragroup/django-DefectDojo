import json
import logging
import textwrap

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


ASSET_FINDING_DESCRIPTION_TEMPLATE = """**Name:** {name}
**Details:**
{description}
**Feed rating:** {feed_rating}
**Published on**: {published_date}
**Reference**: {reference}
**Affected packages:**
{affected_packages}
**Affected systems:**
{affected_systems}
"""


def get_asset_item(vulnerability, test):
    severity = (
        convert_severity(vulnerability.get("severity"))
        if "severity" in vulnerability
        else "Info"
    )

    # usually it is CVE-XXXX-YYYY
    vuln_name = vulnerability.get("name")

    vuln_description = vulnerability.get("description", "").strip()

    published_date = None
    published_ts = vulnerability.get("published_timestamp", 0)
    if published_ts > 0:
        published_date = datetime.fromtimestamp(int(published_ts))

    reference = vulnerability.get("link", "not provided")

    affected_packages = ""

    # will be used to form finding title
    package_names = []

    packages = vulnerability.get("packages", {})
    if len(packages.values()) > 0:
        for package_name, package_versions in packages.items():
            # openssl/libssl3 --> openssl
            shortened_pkgname = package_name.split('/')[0]
            # python:setuptools --> setuptools
            # commons-io:commons-io --> commons-io
            shortened_pkgname = shortened_pkgname.split(':')[-1]

            package_names.append(shortened_pkgname)

            affected_packages += f"*{package_name}*\n"

            for versions in package_versions:
                installed=versions.get("package_version", "unknown")
                fixed=versions.get("fixed_version", "unknown")
                affected_packages += f"  installed version: {installed}\n"
                affected_packages += f"  fixed version: {fixed}\n"

            affected_packages += "\n"

    # there is nothing like short description, short name or title. thus, to
    # form a finding title we take its name (i.e. CVE) and combined with
    # minimized list of the affected packages
    package_names_combined = ','.join(sorted(set(package_names), key=str))
    title_suffix = textwrap.shorten(package_names_combined, width=32, placeholder="...")
    finding_title = f"{vuln_name}: {title_suffix}"

    nodes = vulnerability.get("nodes", [])
    workloads = vulnerability.get("workloads", [])
    images = vulnerability.get("images", [])
    platforms = vulnerability.get("platforms", [])

    # the same information is saved as Endpoint(s), however, DefectDojo
    # Endpoint lacks many metadata fields, thus, difficult to read.
    affected_systems = ""

    for asset in nodes:
        display_name = asset.get("display_name", "")
        domains = ','.join(asset.get("domains", []))
        affected_systems += f"*Node {display_name}*\n"
        affected_systems += f"  domains: {domains}\n"

    for asset in platforms:
        display_name = asset.get("display_name", "")
        domains = ','.join(asset.get("domains", []))
        affected_systems += f"*Platform {display_name}*\n"
        affected_systems += f"  domains: {domains}\n"

    for asset in images:
        display_name = asset.get("display_name", "")
        domains = ','.join(asset.get("domains", []))
        affected_systems += f"*Image {display_name}*\n"
        affected_systems += f"  domains: {domains}\n"

    for asset in workloads:
        display_name = asset.get("display_name", "")
        domains = ','.join(asset.get("domains", []))
        service = asset.get("service", "")
        image = asset.get("image", "")
        affected_systems += f"*Workload {display_name}*\n"
        affected_systems += f"  domains: {domains}\n"
        affected_systems += f"  service: {service}\n"
        affected_systems += f"  image: {image}\n"

    description = ASSET_FINDING_DESCRIPTION_TEMPLATE.format(
        name=vuln_name,
        description=vuln_description,
        feed_rating=vulnerability.get("feed_rating", "not provided"),
        published_date=published_date,
        reference=reference,
        affected_packages=affected_packages,
        affected_systems=affected_systems,
    )

    # create the finding object
    finding = Finding(
        title=finding_title,
        test=test,
        description=description,
        severity=severity,
        impact="",
        references=reference,
        cvssv3=vulnerability.get("vectors_v3", ""),
        cvssv3_score=vulnerability.get("score_v3", ""),
        publish_date=published_date,
    )

    finding.unsaved_vulnerability_ids = [vuln_name]

    finding.unsaved_endpoints = []

    for asset in nodes:
        endpoints = endpoints_from_asset("node", asset)
        finding.unsaved_endpoints += endpoints

    for asset in workloads:
        endpoints = endpoints_from_asset("workload", asset)
        finding.unsaved_endpoints += endpoints

    for asset in images:
        endpoints = endpoints_from_asset("image", asset)
        finding.unsaved_endpoints += endpoints

    for asset in platforms:
        endpoints = endpoints_from_asset("platform", asset)
        finding.unsaved_endpoints += endpoints

    return finding


def endpoints_from_asset(kind, asset):
    endpoints = []

    # usually, there is only one namespace (domain, as NeuVector name it)
    namespaces = asset.get("domains", [])

    name = asset.get("display_name", "")

    if kind == "workload":
        # only workload assets have 'service' field
        service = asset.get("service", "unknown_service")
        name += f"/{service}"

    # in principle, naming follows the approach chosen for trivy parser
    endpoints.append(Endpoint(
        # host needs to comply with domain name syntax, we just expect that
        # there will be only one namespace
        host='-'.join(namespaces),
        # we abuse path to have as much details as possible
        path=f"{kind}/{name}",
    ))

    # if it is a workload and it has an associated image, add image as a
    # separate endpoint
    if kind == "workload" and asset.get("image", "") != "":
        image = asset.get("image", "unknown_image")
        # image value example:
        # someregistry.com/bitnami/postgresql:11.21.0-debian-11-r58
        artifact_and_tag = image.split("/")[-1]
        # extracting only image name, without tag or digest
        artifact_name = artifact_and_tag.split("@")[0]
        artifact_name = artifact_name.split(":")[0]

        endpoints.append(Endpoint(
            host=f"{artifact_name}",
            path=f"{image}",
        ))

    return endpoints

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
