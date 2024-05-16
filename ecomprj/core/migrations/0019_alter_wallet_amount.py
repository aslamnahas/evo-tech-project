# Generated by Django 5.0.2 on 2024-05-16 05:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0018_citydistance'),
    ]

    operations = [
        migrations.AlterField(
            model_name='wallet',
            name='amount',
            field=models.DecimalField(decimal_places=2, default=0, max_digits=10),
        ),
    ]