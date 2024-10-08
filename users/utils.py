import logging
import random
import string
from datetime import timedelta
from string import ascii_letters


from django.conf import settings
from django.core import signing
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from users.models import ResetPasswordOTP, User



import json
import random
import time
import struct
import binascii
from django.template.loader import get_template
from django.core.mail import EmailMessage


logger = logging.getLogger()


def sendmail(subject, message, user_email, username):
    ctx = {"message": message, "subject": subject, "username": username}
    message = get_template("email.html").render(ctx)
    msg = EmailMessage(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user_email],
    )
    msg.content_subtype = "html"  # Main content is now text/html
    msg.send()


def generate_authtoken(user: User) -> dict[str, str]:
    """Generate jwt token."""
    refresh_token = RefreshToken.for_user(user)
    return {
        "access": str(refresh_token.access_token),
        "refresh": str(refresh_token.refresh),
    }


def generate_otp_pin(user: User) -> tuple[int, str]:
    """Generate new otp pin."""
    unsigned_pin = random.randint(100000, 999999)
    signer = signing.TimestampSigner()
    signed_pin = signer.sign_object({"token": unsigned_pin})
    return unsigned_pin, signed_pin


def validate_otp_pin(pin: str, user: User) -> bool:
    """Validate otp pin"""

    otp = (
        ResetPasswordOTP.objects.filter(user=user, is_active=True)
        .order_by("datetime_created")
        .first()
    )

    if not otp:
        return False

    try:
        max_age = timedelta(minutes=otp.duration_in_minutes)

        signer = signing.TimestampSigner()
        data = signer.unsign_object(otp.signed_pin, max_age=max_age)

        if str(data["token"]) == str(pin):
            otp.is_active = False
            otp.save(update_fields=["is_active"])
            return True

    except signing.SignatureExpired:
        pass
    except KeyError as error:
        logger.exception(
            "bmoves::users::api::v1::utils::validate_otp_pin:: keyerror occured",
            stack_info=True,
            extra={"details": str(error.with_traceback())},
        )

    return False


def generate_password_reset_key(user: User) -> tuple[str, str]:
    key = "".join(random.sample(ascii_letters, k=10))
    signer = signing.TimestampSigner()
    signed_key = signer.sign_object({"key": key, "email": user.email})
    return key, signed_key


def generate_email_verification_link(user: User) -> str:
    """Generate email verification link."""
    signer = signing.TimestampSigner()
    signature = signer.sign_object({"email": user.email})
    url = reverse("users_api_v1:email_verification", args=[signature])
    return url


def validate_email_verification_signature(signature: str):
    """Verifies email verification signature."""

    try:
        max_age = timedelta(hours=settings.EMAIL_VERIFCATION_MAX_AGE)
        signer = signing.TimestampSigner()
        data = signer.unsign_object(signature, max_age=max_age)

        email = data["email"]
        return User.objects.filter(email=email).first()
    except (signing.SignatureExpired, signing.BadSignature):
        pass
    except KeyError as error:
        logger.exception(
            "bmoves::users::api::v1::utils::validate_email_verification_signature:: keyerror occured",
            stack_info=True,
            extra={"details": str(error.with_traceback())},
        )
