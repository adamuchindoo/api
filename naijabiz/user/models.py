# user/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid
from .helper import generate_unique_filename


class Region(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


# --- State ---
class State(models.Model):
    name = models.CharField(max_length=100)
    region = models.ForeignKey(Region, on_delete=models.CASCADE, related_name="states")

    def __str__(self):
        return self.name


# --- LGA ---
class LGA(models.Model):
    name = models.CharField(max_length=100)
    state = models.ForeignKey(State, on_delete=models.CASCADE, related_name="lgas")

    def __str__(self):
        return self.name


class User_role(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=10)
    name = models.CharField(max_length=50)

    def __str__(self):
        return self.name


class User(AbstractUser):
    ROLE_CHOICES = [
        ("b2c", "Consumer"),
        ("b2b", "Business"),
        ("mentor", "Mentor"),
        ("msme", "MSME Owner"),
        ("admin", "Admin"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    other_name = models.CharField(max_length=50, blank=True, null=True)
    csrf_token = models.CharField(max_length=100, blank=True, null=True)
    # role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="b2c")
    role = models.ForeignKey(
        User_role,
        on_delete=models.SET_NULL,
        related_name="user_roles",
        blank=True,
        null=True,
    )
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    region = models.ForeignKey(
        Region, on_delete=models.SET_NULL, null=True, blank=True, related_name="region"
    )
    state = models.ForeignKey(
        State, on_delete=models.SET_NULL, null=True, blank=True, related_name="state"
    )
    lga = models.ForeignKey(
        LGA, on_delete=models.SET_NULL, null=True, blank=True, related_name="lga"
    )
    contact_address = models.CharField(max_length=250, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username", "role"]


class EmailValidation(models.Model):
    email = models.EmailField(unique=True)
    code = models.CharField(max_length=6)  # 6-digit OTP
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)


class RefreshSession(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="refresh_sessions"
    )
    token_hash = models.CharField(max_length=256, unique=True)
    user_agent = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"RefreshSession(user={self.user.username}, active={self.is_active})"


class Business_categories(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)


class Market_region(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    state = models.ForeignKey(
        State, on_delete=models.CASCADE, related_name="market_region"
    )


class Business_profile(models.Model):
    BUSINESS_STATUS_CHOICES = [
        ("Verified", "Verified"),
        ("Pending", "Pending"),
        ("Rejected", "Rejected"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="b2b")
    role = models.ForeignKey(
        User_role,
        on_delete=models.SET_NULL,
        related_name="business_roles",
        blank=True,
        null=True,
    )
    business_name = models.CharField(max_length=100)
    category = models.ForeignKey(
        Business_categories,
        on_delete=models.CASCADE,
        related_name="business_categories",
    )
    business_phone_number = models.CharField(max_length=15)
    aditional_phone_number = models.CharField(max_length=20, blank=True, null=True)
    business_address = models.CharField(max_length=200)
    region = models.ForeignKey(
        Region,
        on_delete=models.SET_NULL,
        related_name="business_region",
        blank=True,
        null=True,
    )
    state = models.ForeignKey(
        State,
        on_delete=models.SET_NULL,
        related_name="business_state",
        blank=True,
        null=True,
    )
    lga = models.ForeignKey(
        LGA,
        on_delete=models.SET_NULL,
        related_name="business_lga",
        blank=True,
        null=True,
    )
    market_region = models.ForeignKey(
        Market_region,
        on_delete=models.SET_NULL,
        related_name="market_region",
        blank=True,
        null=True,
    )
    website = models.URLField(max_length=20, blank=True, null=True)
    cac_registration_number = models.CharField(max_length=15)
    cac_file = models.FileField(
        upload_to=generate_unique_filename,
        verbose_name="cac doc",
    )
    trade_license = models.FileField(
        upload_to=generate_unique_filename,
        verbose_name="Trade license",
    )
    tax_identification_number = models.CharField(max_length=20)
    owner_full_name = models.CharField(max_length=100)
    nin_number = models.CharField(max_length=15)
    address = models.CharField(max_length=100)
    business_status = models.CharField(
        max_length=50, choices=BUSINESS_STATUS_CHOICES, default="Pending"
    )


class Expertise_area(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)


class Professional_profile(models.Model):
    PROFILE_STATUS_CHOICES = [
        ("Verified", "Verified"),
        ("Pending", "Pending"),
        ("Rejected", "Rejected"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="professional_user"
    )
    role = models.ForeignKey(
        User_role,
        on_delete=models.SET_NULL,
        related_name="professional_roles",
        blank=True,
        null=True,
    )
    full_name = models.CharField(max_length=100)
    short_bio = models.CharField(max_length=200)
    years_of_experiance = models.CharField(max_length=10)
    expertise_area = models.ForeignKey(
        Expertise_area,
        on_delete=models.SET_NULL,
        related_name="expertise_area",
        blank=True,
        null=True,
    )
    website = models.URLField(max_length=20, blank=True, null=True)
    certificate_file = models.FileField(
        upload_to=generate_unique_filename,
        verbose_name="Professional certificate",
    )
    certification_reg_no = models.CharField(max_length=30)
    tax_identification_number = models.CharField(max_length=20)
    profile_status = models.CharField(
        max_length=50, choices=PROFILE_STATUS_CHOICES, default="Pending"
    )
