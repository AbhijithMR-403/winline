# Generated by Django 5.0.4 on 2024-05-30 13:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0011_alter_location_country_alter_location_district_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='marital_status',
            field=models.CharField(blank=True, choices=[('', 'Blank'), ('married', 'Married'), ('single', 'Unmarried'), ('widowed', 'Widowed'), ('separated', 'Separated'), ('divorced', 'Divorced'), ('other', 'Other')], max_length=30),
        ),
        migrations.AlterField(
            model_name='location',
            name='city',
            field=models.CharField(blank=True, max_length=55, null=True),
        ),
    ]
