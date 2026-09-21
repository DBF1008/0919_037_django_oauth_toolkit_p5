# Resource Indicators (RFC 8707) fields for test swappable models

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("tests", "0008_sampledevicegrant"),
    ]

    operations = [
        migrations.AddField(
            model_name="basetestapplication",
            name="allowed_resources",
            field=models.TextField(
                blank=True,
                default="",
                help_text="Allowed resource indicators (RFC 8707), space separated",
            ),
        ),
        migrations.AddField(
            model_name="sampleapplication",
            name="allowed_resources",
            field=models.TextField(
                blank=True,
                default="",
                help_text="Allowed resource indicators (RFC 8707), space separated",
            ),
        ),
        migrations.AddField(
            model_name="samplegrant",
            name="resources",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="sampleaccesstoken",
            name="resources",
            field=models.TextField(blank=True, default=""),
        ),
    ]
