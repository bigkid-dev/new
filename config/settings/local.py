"""
Django settings for data_epic project local environment.


For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from .base import *

SECRET_KEY = "django-insecure-xe(h20#e$iw#sfwq#sjd*$0m6axap2-06-&&7ub2up!2ar7*z%"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}