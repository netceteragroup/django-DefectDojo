import logging

from django.db import migrations

logger = logging.getLogger(__name__)

TEST_TYPE_NAME = "Trivy Operator Scan"
BATCH_SIZE = 1000


def set_trivy_operator_findings_dynamic(apps, schema_editor):
    """
    Flag existing Trivy Operator findings as dynamic findings.

    The Trivy Operator parser attaches endpoints (the affected Kubernetes resources) to its
    findings, but used to create them with `dynamic_finding=False`. The reimporter only
    mitigates/reactivates endpoints of findings flagged as `dynamic_finding`
    (see dojo/importers/default_reimporter.py), so those findings accumulated endpoints that
    were never mitigated once the resource disappeared from the report.

    The parser has been fixed, but the reimporter reads the stored value of the already
    existing finding, so existing rows have to be backfilled as well.

    `queryset.update()` is used on purpose: it bypasses signals, auditlog and hash_code
    recomputation. This is safe because `Trivy Operator Scan` deduplicates on
    ["title", "severity", "vulnerability_ids", "description"], so `hash_code` does not
    depend on `static_finding`/`dynamic_finding` or on endpoints.
    """
    Finding = apps.get_model("dojo", "Finding")

    base_qs = Finding.objects.filter(
        test__test_type__name=TEST_TYPE_NAME,
        dynamic_finding=False,
    )

    total = 0
    while True:
        batch_ids = list(base_qs.values_list("id", flat=True)[:BATCH_SIZE])
        if not batch_ids:
            break
        updated = Finding.objects.filter(id__in=batch_ids).update(dynamic_finding=True)
        total += updated
        if updated == 0:
            # Safety net: nothing changed, avoid looping forever
            break

    logger.info("Flagged %d '%s' findings as dynamic_finding", total, TEST_TYPE_NAME)


class Migration(migrations.Migration):

    # Fork-only migration: numbers >= 0999 are reserved for migrations that will never be
    # contributed upstream, so they cannot collide with upstream numbering.
    #
    # Fork migrations form their own chain, each depending on the previous fork migration.
    # Never use `run_before` to place a fork migration in front of an already applied one:
    # `run_before` creates a graph edge that Django's consistency check follows, and an
    # already applied migration pointing at an unapplied one raises
    # InconsistentMigrationHistory on every existing deployment.
    #
    # When a new upstream migration is cherry-picked, the dojo app temporarily has two leaf
    # nodes (the upstream one and this chain). Resolve it with a merge migration:
    #     python manage.py makemigrations --merge dojo
    # and rename the generated file into the fork range (>= 1001).
    dependencies = [
        ("dojo", "0999_alter_dojo_group_social_provider"),
    ]

    operations = [
        # Irreversible on purpose: the previous per-finding value cannot be reconstructed.
        migrations.RunPython(
            set_trivy_operator_findings_dynamic,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
