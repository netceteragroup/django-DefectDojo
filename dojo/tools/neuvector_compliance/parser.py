import hashlib
import json

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

    finding = Finding(
        title=title,
        test=test,
        description=full_description,
        severity=severity,
        mitigation=mitigation,
        vuln_id_from_tool=vuln_id_from_tool,
        static_finding=True,
        dynamic_finding=False,
    )

    return finding


def get_asset_item(comp_issue, test):
    test_name = comp_issue.get("name", "unknown")

    test_description = comp_issue.get("description", "").rstrip()

    test_severity = comp_issue.get("level", "unknown")

    mitigation = comp_issue.get("remediation", "").rstrip()

    category = comp_issue.get("category", "unknown")

    test_profile = comp_issue.get("profile", "unknown")

    full_description = "<p>{} ({}), {}:</p>".format(
        test_name, category, test_profile
    )
    full_description += "<p>{}</p>".format(test_description)
    full_description += "<p>Audit: {}</p>".format(test_severity)
    full_description += "<p>Mitigation:</p>"
    full_description += "<p>  {}</p>".format(mitigation)

    tags = comp_issue.get("tags", [])
    if len(tags) > 0:
        full_description += "<p>Applicable compliance standards: {tags}</p>".format(tags=','.join(sorted(set(tags), key=str)))

    messages = comp_issue.get("message", [])
    if len(messages) > 0:
        full_description += "<p>Messages:</p>"
        for m in messages:
            full_description += "<p>  {}</p>".format(str(m).rstrip())

    finding = Finding(
        title="{name} - {desc}".format(name=test_name, desc=test_description),
        test=test,
        description=full_description,
        severity=convert_severity(test_severity),
        mitigation=mitigation,
        vuln_id_from_tool="{category}_{name}".format(category=category, name=test_name),
        impact="",
        static_finding=True,
        dynamic_finding=False,
    )

    finding.unsaved_vulnerability_ids = []

    finding.unsaved_endpoints = []

    nodes = comp_issue.get("nodes", [])
    for node in nodes:
        endpoint = Endpoint(
            host=node.get("display_name", ""),
        )
        finding.unsaved_endpoints.append(endpoint)

    return finding


# see neuvector/share/clus_apis.go
def convert_severity(severity):
    if severity.lower() == "high":
        return "High"
    elif severity.lower() == "warn":
        return "Medium"
    elif severity.lower() == "info":
        return "Low"
    elif severity.lower() == "pass":
        return "Info"
    elif severity.lower() == "note":
        return "Info"
    elif severity.lower() == "error":
        return "Info"
    elif severity.lower() == "manual":
        return "Info"
    else:
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
        else:
            msg = "Unknown File Format"
            raise ValueError(msg)
