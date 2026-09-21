# Generated for RFC 8707 Resource Indicators support

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("oauth2_provider", "0014_alter_help_text"),
    ]

    operations = [
        migrations.AddField(
            model_name="application",
            name="allowed_resources",
            field=models.TextField(
                blank=True,
                default="",
                help_text="Allowed resource indicators (RFC 8707), space separated",
            ),
        ),
        migrations.AddField(
            model_name="grant",
            name="resources",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="accesstoken",
            name="resources",
            field=models.TextField(blank=True, default=""),
        ),
    ]
