# Generated by Django 5.0.2 on 2024-02-22 12:22

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('prowler_app', '0015_awsmodal'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='awsmodal',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='Awsmodal', to=settings.AUTH_USER_MODEL),
        ),
    ]
