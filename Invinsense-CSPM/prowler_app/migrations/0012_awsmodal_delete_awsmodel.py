# Generated by Django 5.0.2 on 2024-02-08 10:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('prowler_app', '0011_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AWSModal',
            fields=[
                ('username', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('aws_account_id', models.CharField(max_length=100)),
            ],
        ),
        migrations.DeleteModel(
            name='AwsModel',
        ),
    ]
