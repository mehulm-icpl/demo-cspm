# Generated by Django 5.0.1 on 2024-03-11 08:13

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('prowler_app', '0019_alter_awsmodal_user'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Azuremodal',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('azure_tenant_id', models.CharField(default=None, max_length=100)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='azuremodal', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
