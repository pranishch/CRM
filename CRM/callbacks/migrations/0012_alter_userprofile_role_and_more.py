# Generated by Django 5.2.3 on 2025-07-03 12:06

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('callbacks', '0011_alter_callback_options'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.CharField(choices=[('Agent', 'Agent'), ('Manager', 'Manager'), ('Admin', 'Admin')], default='Agent', max_length=20),
        ),
        migrations.AddIndex(
            model_name='callback',
            index=models.Index(fields=['created_by', 'created_at'], name='callbacks_c_created_d46080_idx'),
        ),
    ]
