# user/utils.py
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes


def send_verification_email(request, user):
    from .tokens import account_activation_token  # Local import to avoid circular

    token = account_activation_token.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    domain = get_current_site(request).domain
    verify_url = f"{request.scheme}://{domain}/user/verify-email/{uid}/{token}/"

    subject = "Verify Your Email"
    body = f"""
    Hello {user.username},

    Please verify your email by clicking the link below:
    {verify_url}

    This link expires in 24 hours.
    """
    send_mail(
        subject,
        body,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )
