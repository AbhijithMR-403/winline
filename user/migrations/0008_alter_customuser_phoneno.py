# Generated by Django 5.0.4 on 2024-05-23 09:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0007_alter_customuser_email_alter_customuser_phoneno'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='phoneno',
            field=models.CharField(max_length=20, unique=True),
        ),
    ]
