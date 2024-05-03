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


def get_asset_item(vulnerability, test):
    severity = (
        convert_severity(vulnerability.get("severity"))
        if "severity" in vulnerability
        else "Info"
    )

    feed_rating = vulnerability.get("feed_rating", "")

    description = vulnerability.get("description", "").strip()

    if len(feed_rating) > 0:
        description += "<p>Rating from vendor: {rating}</p>".format(rating=feed_rating)

    mitigation = ""

    package_names = []

    packages = vulnerability.get("packages", {})
    if len(packages.values()) > 0:
        mitigation += "<p>update the affected packages to the following versions:</p>"
        description += "<p>The following packages are affected:</p>"

        for package_name, package_versions in packages.items():
            package_names.append(package_name.split('/')[0])

            mitigation += "<p>{name}:</p>".format(name=package_name)

            description += "<p>{name}:</p>".format(name=package_name)
            for versions in package_versions:
                mitigation += "<p>  {fixed}</p>".format(fixed=versions.get("fixed_version", "unknown"))

                description += "<p>  installed version: {installed}</p>".format(installed=versions.get("package_version", "unknown"))
                description += "<p>  fixed version: {fixed}</p>".format(fixed=versions.get("fixed_version", "unknown"))

    link = vulnerability.get("link") if "link" in vulnerability else ""

    vectors_v3 = vulnerability.get("vectors_v3", "")

    score_v3 = vulnerability.get("score_v3", "")

    published_date = None
    published_ts = vulnerability.get("published_timestamp", 0)
    if published_ts > 0:
        published_date = datetime.fromtimestamp(int(published_ts))

    vulnerability_id = vulnerability.get("name")

    # there is nothing like short description, short name or title
    package_names_combined = ','.join(sorted(set(package_names), key=str))
    if len(package_names_combined) > 32:
        package_names_combined = package_names_combined[-32:]

    title = "{packages}: ({vuln})".format(packages=package_names_combined, vuln=vulnerability.get("name").upper())

    # create the finding object
    finding = Finding(
        title=title,
        test=test,
        description=description,
        severity=severity,
        mitigation=mitigation,
        impact="",
        url=link,
        cvssv3=vectors_v3,
        cvssv3_score=score_v3,
        publish_date=published_date,
    )

    finding.unsaved_vulnerability_ids = [vulnerability_id]

    finding.unsaved_endpoints = []

    nodes = vulnerability.get("nodes", [])
    for node in nodes:
        endpoint = Endpoint(
            host=node.get("display_name", ""),
        )
        finding.unsaved_endpoints.append(endpoint)

    return finding


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
