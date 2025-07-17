# CRM/settings/dev.py
from .base import *

DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1', 'localhost']

CSRF_TRUSTED_ORIGINS = []

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static')
]

SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
