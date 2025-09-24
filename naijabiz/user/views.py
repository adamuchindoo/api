# user/views.py
from ninja import Router
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str

from naijabiz import settings

from .models import User
from .schemas import UserOut, UserRegister, UserLogin, SetNewPassword
from .utils import send_verification_email
from .tokens import account_activation_token

router = Router()
User = get_user_model()  # Reuse User model


# ------------------ REGISTER ------------------
@router.post("/register", response={201: UserOut, 400: dict})
def register(request: HttpRequest, data: UserRegister):
    if data.password != data.confirm_password:
        return 400, {"message": "Passwords do not match"}

    if User.objects.filter(email=data.email).exists():
        return 400, {"message": "Email already registered"}

    user = User.objects.create_user(
        username=data.username,
        email=data.email,
        password=data.password,
        role=data.role,
        phone=data.phone,
        is_active=False,  # Wait for email verification
    )

    send_verification_email(request, user)
    return 201, user


# ------------------ VERIFY EMAIL ------------------
@router.get("/verify-email/{uidb64}/{token}/", response={200: dict, 400: dict})
def verify_email(request: HttpRequest, uidb64: str, token: str):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_object_or_404(User, pk=uid)
    except Exception:
        return 400, {"message": "Invalid verification link"}

    if account_activation_token.check_token(user, token):
        user.is_verified = True
        user.is_active = True
        user.save()
        return 200, {"message": "Email verified successfully. You can now log in."}
    else:
        return 400, {"message": "Invalid or expired token"}


# ------------------ LOGIN ------------------
@router.post("/login", response={200: dict, 401: dict})
def login_user(request: HttpRequest, data: UserLogin):
    user = authenticate(email=data.email, password=data.password)
    if not user:
        return 401, {"message": "Invalid credentials"}

    if not user.is_active:
        return 401, {"message": "Account not activated. Check your email."}

    login(request, user)
    return 200, {
        "message": "Login successful",
        "user": UserOut.from_orm(user),
        "token": "your-jwt-token-here",  # Replace with real JWT later
    }


# ------------------ LOGOUT ------------------
@router.post("/logout", response={200: dict})
def logout_user(request: HttpRequest):
    logout(request)
    return 200, {"message": "Logged out successfully"}


# ------------------ PROFILE ------------------
@router.get("/me", response=UserOut)
def get_profile(request: HttpRequest):
    if not request.user.is_authenticated:
        return 401, {"message": "Authentication required"}
    return request.user


# ------------------ UPDATE PROFILE ------------------
@router.put("/me", response=UserOut)
def update_profile(request: HttpRequest, phone: str = None, username: str = None):
    if not request.user.is_authenticated:
        return 401, {"message": "Authentication required"}

    user = request.user
    if username:
        user.username = username
    if phone:
        user.phone = phone
    user.save()
    return user


def urlsafe_base64_encode(s):
    raise NotImplementedError


def force_bytes(value):
    raise NotImplementedError


def get_current_site(request):
    raise NotImplementedError


def send_mail(subject, message, from_email, recipient_list, fail_silently):
    raise NotImplementedError


# ------------------ FORGOT PASSWORD ------------------
@router.post("/forgot-password", response={200: dict, 404: dict})
def forgot_password(request: HttpRequest, email: str):
    try:
        user = User.objects.get(email=email, is_active=True)
    except User.DoesNotExist:
        return 404, {"message": "Email not found"}

    token = account_activation_token.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    domain = get_current_site(request).domain
    reset_url = f"{request.scheme}://{domain}/user/reset-password/{uid}/{token}/"

    send_mail(
        "Password Reset Request",
        f"Click here to reset your password: {reset_url}",
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )
    return 200, {"message": "Password reset link sent to your email."}


# ------------------ RESET PASSWORD ------------------
@router.post("/reset-password/{uidb64}/{token}/", response={200: dict, 400: dict})
def reset_password(request: HttpRequest, uidb64: str, token: str, data: SetNewPassword):
    if data.password != data.confirm_password:
        return 400, {"message": "Passwords do not match"}

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_object_or_404(User, pk=uid)
    except Exception:
        return 400, {"message": "Invalid link"}

    if not account_activation_token.check_token(user, token):
        return 400, {"message": "Invalid or expired token"}

    user.set_password(data.password)
    user.save()
    return 200, {"message": "Password updated successfully."}
