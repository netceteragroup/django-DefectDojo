import logging

from django.test import override_settings

from dojo.models import Endpoint_Status, Finding, User

from .dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)

WORKLOAD_ENDPOINT = "ReplicaSet/nginx-deployment-965685897/nginx"
OLD_IMAGE_ENDPOINT = "index.docker.io/library/nginx:alpine"
NEW_IMAGE_ENDPOINT = "index.docker.io/library/nginx:alpine-3.19"


@override_settings(V3_FEATURE_LOCATIONS=False)
class TrivyOperatorReimportTest(DojoAPITestCase):

    """
    Regression tests for the endpoint lifecycle of Trivy Operator findings.

    Trivy Operator findings carry endpoints (the affected Kubernetes resource and the
    scanned image). The reimporter only mitigates/reactivates endpoints of findings flagged
    as `dynamic_finding` (see dojo/importers/default_reimporter.py). The parser used to
    create findings with `dynamic_finding=False`, so endpoints were only ever added and
    never mitigated once they disappeared from the report.

    `Trivy Operator Scan` deduplicates on title/severity/vulnerability_ids/description, so
    the same finding is matched on reimport even though its endpoints changed.
    """

    fixtures = ["dojo_testdata.json"]

    scan_type = "Trivy Operator Scan"

    def setUp(self):
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self.login_as_admin()
        self.old_image = get_unit_tests_scans_path("trivy_operator") / "vulnerabilityreport_image_tag_old.json"
        self.new_image = get_unit_tests_scans_path("trivy_operator") / "vulnerabilityreport_image_tag_new.json"

    def _import_old_image(self):
        return self.import_scan_with_params(self.old_image, scan_type=self.scan_type)["test"]

    def _get_single_finding(self, test_id):
        findings = Finding.objects.filter(test=test_id)
        self.assertEqual(1, findings.count())
        return findings.first()

    @staticmethod
    def _endpoint_status_by_path(finding):
        return {
            endpoint_status.endpoint.path: endpoint_status
            for endpoint_status in Endpoint_Status.objects.filter(finding=finding).select_related("endpoint")
        }

    def test_imported_finding_is_static_and_dynamic(self):
        finding = self._get_single_finding(self._import_old_image())
        self.assertTrue(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

    def test_import_creates_workload_and_image_endpoints(self):
        finding = self._get_single_finding(self._import_old_image())
        statuses = self._endpoint_status_by_path(finding)
        self.assertEqual({WORKLOAD_ENDPOINT, OLD_IMAGE_ENDPOINT}, set(statuses.keys()))
        self.assertFalse(any(endpoint_status.mitigated for endpoint_status in statuses.values()))

    def test_reimport_mitigates_endpoint_absent_from_report(self):
        test_id = self._import_old_image()

        self.reimport_scan_with_params(test_id, self.new_image, scan_type=self.scan_type)

        finding = self._get_single_finding(test_id)
        self.assertFalse(finding.is_mitigated, "the finding is still reported, only its image endpoint changed")
        statuses = self._endpoint_status_by_path(finding)
        self.assertEqual({WORKLOAD_ENDPOINT, OLD_IMAGE_ENDPOINT, NEW_IMAGE_ENDPOINT}, set(statuses.keys()))
        self.assertTrue(
            statuses[OLD_IMAGE_ENDPOINT].mitigated,
            "endpoint that disappeared from the report must be mitigated",
        )
        self.assertIsNotNone(statuses[OLD_IMAGE_ENDPOINT].mitigated_time)
        self.assertFalse(statuses[WORKLOAD_ENDPOINT].mitigated)
        self.assertFalse(statuses[NEW_IMAGE_ENDPOINT].mitigated)

    def test_reimport_reactivates_endpoint_present_again(self):
        test_id = self._import_old_image()
        self.reimport_scan_with_params(test_id, self.new_image, scan_type=self.scan_type)

        self.reimport_scan_with_params(test_id, self.old_image, scan_type=self.scan_type)

        finding = self._get_single_finding(test_id)
        statuses = self._endpoint_status_by_path(finding)
        self.assertFalse(
            statuses[OLD_IMAGE_ENDPOINT].mitigated,
            "endpoint that reappeared in the report must be reactivated",
        )
        self.assertIsNone(statuses[OLD_IMAGE_ENDPOINT].mitigated_time)
        self.assertTrue(statuses[NEW_IMAGE_ENDPOINT].mitigated)
        self.assertFalse(statuses[WORKLOAD_ENDPOINT].mitigated)
