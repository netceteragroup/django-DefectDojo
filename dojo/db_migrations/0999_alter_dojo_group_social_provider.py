from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0264_alter_url_identity_hash_alter_urlevent_identity_hash'),
    ]

    operations = [
        migrations.AlterField(
            model_name='dojo_group',
            name='social_provider',
            field=models.CharField(blank=True, choices=[('AzureAD', 'AzureAD'), ('Remote', 'Remote'), ('Keycloak', 'Keycloak')], help_text='Group imported from a social provider.', max_length=10, null=True, verbose_name='Social Authentication Provider'),
        ),
    ]
