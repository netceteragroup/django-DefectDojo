"""Parser for Aquasecurity trivy-operator (https://github.com/aquasecurity/trivy-operator)"""

import json

from dojo.tools.trivy_operator.checks_handler import TrivyChecksHandler
from dojo.tools.trivy_operator.clustercompliance_handler import TrivyClusterComplianceHandler
from dojo.tools.trivy_operator.compliance_handler import TrivyComplianceHandler
from dojo.tools.trivy_operator.secrets_handler import TrivySecretsHandler
from dojo.tools.trivy_operator.vulnerability_handler import TrivyVulnerabilityHandler

from dojo.models import Endpoint


class TrivyOperatorParser:
    def get_scan_types(self):
        return ["Trivy Operator Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Trivy Operator Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import trivy-operator JSON scan report."

    def get_findings(self, scan_file, test):
        scan_data = scan_file.read()
        try:
            data = json.loads(str(scan_data, "utf-8"))
        except Exception:
            data = json.loads(scan_data)
        findings = []
        if type(data) is list:
            for listitems in data:
                findings += self.output_findings(listitems, test)
        elif type(data) is dict and bool(set(data.keys()) & {"clustercompliancereports.aquasecurity.github.io", "clusterconfigauditreports.aquasecurity.github.io", "clusterinfraassessmentreports.aquasecurity.github.io", "clusterrbacassessmentreports.aquasecurity.github.io", "configauditreports.aquasecurity.github.io", "exposedsecretreports.aquasecurity.github.io", "infraassessmentreports.aquasecurity.github.io", "rbacassessmentreports.aquasecurity.github.io", "vulnerabilityreports.aquasecurity.github.io"}):
            for datakey in list(data.keys()):
                if datakey not in {"clustersbomreports.aquasecurity.github.io", "sbomreports.aquasecurity.github.io"}:
                    for listitems in (data[datakey]):
                        findings += self.output_findings(listitems, test)
        else:
            findings += self.output_findings(data, test)
        return findings

    def output_findings(self, data, test):
        findings = []
        if data is None:
            return []

        if isinstance(data, dict):
            findings = self.handle_resource(data, test)
        else:
            for resource in data:
                findings += self.handle_resource(resource, test)
        return findings

    def handle_resource(self, data, test):
        metadata = data.get("metadata", None)
        if metadata is None:
            return []
        labels = metadata.get("labels", None)
        if labels is None:
            return []
        report = data.get("report", None)
        if report is not None:
            resource_namespace = labels.get(
                "trivy-operator.resource.namespace", "",
            )
            resource_kind = labels.get("trivy-operator.resource.kind", "")
            resource_name = labels.get("trivy-operator.resource.name", "")
            container_name = labels.get("trivy-operator.container.name", "")

            endpoints = []
            endpoints.append(Endpoint(
                host=resource_namespace,
                path=f"{resource_kind}/{resource_name}/{container_name}"
            ))

            if report.get("registry"):
                if report.get("artifact"):
                    registry = report.get("registry").get("server", "unknown_registry")
                    artifact = report.get("artifact")
                    repository = artifact.get("repository", "unknown_repo")
                    tag = artifact.get("tag", "")
                    if tag == "":
                        tag = artifact.get("digest", "unknown_tag")
                    # having full path to an image (forward slashes) and a tag
                    # after colon as 'host' property of Endpoint makes an
                    # endpoint broken, although, this is a desired value. Thus,
                    # we abuse 'path' field for that.
                    artifact_name = repository.split("/")[-1]
                    endpoints.append(Endpoint(
                        host=f"{artifact_name}",
                        path=f"{registry}/{repository}:{tag}"
                    ))

            service = ""

            vulnerabilities = report.get("vulnerabilities", None)
            if vulnerabilities is not None:
                findings += TrivyVulnerabilityHandler().handle_vulns(labels, endpoint, service, vulnerabilities, test)
            checks = report.get("checks", None)
            if checks is not None:
                findings += TrivyChecksHandler().handle_checks(labels, endpoint, service, checks, test)
            secrets = report.get("secrets", None)
            if secrets is not None:
                findings += TrivySecretsHandler().handle_secrets(labels, endpoint, service, secrets, test)
        status = data.get("status", None)
        if status is not None:
            benchmarkreport = status.get("detailReport", None)
            if benchmarkreport is not None:
                findings += TrivyComplianceHandler().handle_compliance(benchmarkreport, test)
            clustercompliance = status.get("summaryReport", None)
            if clustercompliance is not None:
                if int(status.get("summary").get("failCount", 0)) > 0:
                    findings += TrivyClusterComplianceHandler().handle_clustercompliance(controls=data.get("spec").get("compliance").get("controls"), clustercompliance=clustercompliance, test=test)
        return findings
