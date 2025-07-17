# CRM/settings/prod.py
from .base import *

DEBUG = False

ALLOWED_HOSTS = ['crm-b6a4.onrender.com']
CSRF_TRUSTED_ORIGINS = ['https://crm-b6a4.onrender.com']

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
