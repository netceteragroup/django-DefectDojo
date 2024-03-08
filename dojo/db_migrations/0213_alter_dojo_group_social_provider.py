# Generated by Django 4.1.13 on 2024-04-11 12:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0212_sla_configuration_enforce_critical_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='dojo_group',
            name='social_provider',
            field=models.CharField(blank=True, choices=[('AzureAD', 'AzureAD'), ('Remote', 'Remote'), ('Keycloak', 'Keycloak')], help_text='Group imported from a social provider.', max_length=10, null=True, verbose_name='Social Authentication Provider'),
        ),
    ]
