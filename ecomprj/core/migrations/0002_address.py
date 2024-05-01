# Generated by Django 5.0.2 on 2024-04-25 08:12

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Address',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address_name', models.CharField(blank=True, max_length=50)),
                ('first_name', models.CharField(blank=True, max_length=50)),
                ('last_name', models.CharField(blank=True, max_length=50)),
                ('email', models.EmailField(max_length=254)),
                ('address_1', models.CharField(blank=True, max_length=250)),
                ('address_2', models.CharField(blank=True, max_length=250)),
                ('country', models.CharField(max_length=15)),
                ('state', models.CharField(max_length=15)),
                ('city', models.CharField(max_length=15)),
                ('pin', models.IntegerField()),
                ('is_deleted', models.BooleanField(default=False)),
                ('default', models.BooleanField(default=False)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
