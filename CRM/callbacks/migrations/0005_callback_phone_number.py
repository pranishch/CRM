# Generated by Django 5.2.3 on 2025-07-02 13:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('callbacks', '0004_remove_callback_created_by_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='callback',
            name='phone_number',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]
