from django.db import models

# Create your models here.
from django.db import models

# Create your models here.
import uuid

from django.contrib.auth.models import AbstractUser
from django.core import signing
from django.db import models
from django.utils.translation import gettext_lazy as _


class User(AbstractUser):
    """Default custom user model for Realty."""

    first_name = None  # type: ignore
    last_name = None  # type: ignore

    id = models.UUIDField(
        default=uuid.uuid4, unique=True, db_index=True, editable=False, primary_key=True
    )
    name = models.CharField(_("Name of User"), max_length=255)
    profile_picture = models.ImageField(
        upload_to="media/profiles/", null=True, blank=True, max_length=300
    )
    phone_number = models.CharField(max_length=255,null=True, blank=True,unique=True)

    password_reset_key = models.CharField(max_length=100, blank=True, null=True)


class ResetPasswordOTP(models.Model):
    id = models.UUIDField(
        default=uuid.uuid4, unique=True, db_index=True, editable=False, primary_key=True
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    signed_pin = models.CharField(max_length=1000)
    is_active = models.BooleanField(default=True)
    is_expired = models.BooleanField(default=False)
    duration_in_minutes = models.IntegerField(default=10)
    datetime_created = models.DateTimeField(auto_now_add=True)



