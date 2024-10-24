import hashlib
import json
import textwrap

from dojo.models import Endpoint,Finding

NEUVECTOR_SCAN_NAME = "NeuVector (compliance)"


def parse(json_output, test):
    tree = parse_json(json_output)
    items = []
    if tree:
        items = list(get_items(tree, test))
    return items


def parse_json(json_output):
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


def get_items(tree, test):
    items = {}

    # if 'report' is in the tree, it means that we received an export from
    # endpoints like /v1/scan/workload/{id}. otherwize, it is an export from
    # /v1/host/{id}/compliance or similar. thus, we need to support items in a
    # bit different leafs.
    testsTree = []
    if "report" in tree:
        testsTree = tree.get("report").get("checks", [])
    elif "items" in tree:
        testsTree = tree.get("items", [])

    for node in testsTree:
        item = get_item(node, test)
        unique_key = (
            node.get("type")
            + node.get("category")
            + node.get("test_number")
            + node.get("description")
        )
        unique_key = hashlib.md5(unique_key.encode("utf-8")).hexdigest()
        items[unique_key] = item

    # asset-style collection with compliance issues of several assets
    testsAssetsTree = []
    if "compliance_issues" in tree:
        testsAssetsTree = tree.get("compliance_issues", [])
        for node in testsAssetsTree:
            item = get_asset_item(node, test)
            unique_key = (
                node.get("name")
                + node.get("category")
                + node.get("type")
                + node.get("level")
                + node.get("profile")
            )
            unique_key = hashlib.md5(unique_key.encode("utf-8")).hexdigest()
            items[unique_key] = item

    return list(items.values())


def get_item(node, test):
    if "test_number" not in node:
        return None
    if "category" not in node:
        return None
    if "description" not in node:
        return None
    if "level" not in node:
        return None

    test_number = node.get("test_number")
    test_description = node.get("description").rstrip()

    title = test_number + " - " + test_description

    test_severity = node.get("level")
    severity = convert_severity(test_severity)

    mitigation = node.get("remediation", "").rstrip()

    category = node.get("category")

    vuln_id_from_tool = category + "_" + test_number

    test_profile = node.get("profile", "profile unknown")

    full_description = f"{test_number} ({category}), {test_profile}:\n"
    full_description += f"{test_description}\n"
    full_description += f"Audit: {test_severity}\n"
    if "evidence" in node:
        full_description += "Evidence:\n{}\n".format(node.get("evidence"))
    if "location" in node:
        full_description += "Location:\n{}\n".format(node.get("location"))
    full_description += f"Mitigation:\n{mitigation}\n"

    tags = node.get("tags", [])
    if len(tags) > 0:
        full_description += "Tags:\n"
        for t in tags:
            full_description += f"{str(t).rstrip()}\n"

    messages = node.get("message", [])
    if len(messages) > 0:
        full_description += "Messages:\n"
        for m in messages:
            full_description += f"{str(m).rstrip()}\n"

    return Finding(
        title=title,
        test=test,
        description=full_description,
        severity=severity,
        mitigation=mitigation,
        vuln_id_from_tool=vuln_id_from_tool,
        static_finding=True,
        dynamic_finding=False,
    )

COMPLIANCE_ASSET_FINDING_DESCRIPTION_TEMPLATE = """**Name:** {name}
**Details:**
{description}
**Audit:** {severity}
**Mitigation**: {mitigation}
**Applicable compliance standards**: {tags}
**Message:**
{message}
**Affected systems:**
{affected_systems}
"""


def get_asset_item(comp_issue, test):
    test_name = comp_issue.get("name", "unknown name")
    test_description = comp_issue.get("description", "").rstrip()

    test_severity = comp_issue.get("level", "")
    severity = convert_severity(test_severity)

    mitigation = comp_issue.get("remediation", "").rstrip()

    category = comp_issue.get("category", "unknown")

    test_group = comp_issue.get("group", "unknown")

    vuln_id_from_tool = f"{category}_{test_name}"

    test_profile = comp_issue.get("profile", "unknown profile")

    tags = comp_issue.get("tags", [])
    messages = comp_issue.get("message", [])

    nodes = comp_issue.get("nodes", [])
    workloads = comp_issue.get("workloads", [])
    images = comp_issue.get("images", [])
    platforms = comp_issue.get("platforms", [])

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

    full_description = COMPLIANCE_ASSET_FINDING_DESCRIPTION_TEMPLATE.format(
        name=f"{test_name} ({category}), {test_profile}, {test_group}",
        description=test_description,
        severity=test_severity,
        mitigation=mitigation,
        tags=';'.join(tags),
        message="\n".join(messages),
        affected_systems=affected_systems,
    )

    finding = Finding(
        title=textwrap.shorten(f"{test_name} - {test_description}", width=64, placeholder="..."),
        test=test,
        description=full_description,
        severity=severity,
        mitigation=mitigation,
        vuln_id_from_tool=vuln_id_from_tool,
        impact="",
        static_finding=True,
        dynamic_finding=False,
    )

    finding.unsaved_vulnerability_ids = [vuln_id_from_tool]

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

# see neuvector/share/clus_apis.go
def convert_severity(severity):
    if severity.lower() == "high":
        return "High"
    if severity.lower() == "warn":
        return "Medium"
    if severity.lower() == "info":
        return "Low"
    if severity.lower() == "pass":
        return "Info"
    if severity.lower() == "note":
        return "Info"
    if severity.lower() == "error":
        return "Info"
    if severity.lower() == "manual":
        return "Info"
    return severity.title()


class NeuVectorComplianceParser:
    def get_scan_types(self):
        return [NEUVECTOR_SCAN_NAME]

    def get_label_for_scan_types(self, scan_type):
        return NEUVECTOR_SCAN_NAME

    def get_description_for_scan_types(self, scan_type):
        return "Imports compliance scans returned by REST API."

    def get_findings(self, filename, test):
        if filename is None:
            return []

        if filename.name.lower().endswith(".json"):
            return parse(filename, test)
        msg = "Unknown File Format"
        raise ValueError(msg)
