import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CRM.settings')
django.setup()
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin123@example.com', 'admin12@15')