# Generated by Django 5.2.3 on 2025-07-06 09:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('callbacks', '0013_remove_userprofile_department_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='callback',
            name='details',
        ),
        migrations.AddField(
            model_name='callback',
            name='notes',
            field=models.TextField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='callback',
            name='website',
            field=models.URLField(blank=True, max_length=255, null=True),
        ),
    ]
