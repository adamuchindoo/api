# user/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser


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


class User(AbstractUser):
    ROLE_CHOICES = [
        ("b2c", "Consumer"),
        ("b2b", "Business"),
        ("mentor", "Mentor"),
        ("msme", "MSME Owner"),
        ("admin", "Admin"),
    ]
    other_name = models.CharField(max_length=50, blank=True, null=True)
    csrf_token = models.CharField(max_length=100, blank=True, null=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="b2c")
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    region = models.ForeignKey(Region, on_delete=models.SET_NULL, null=True, blank=True, related_name="region")
    state = models.ForeignKey(State, on_delete=models.SET_NULL, null=True, blank=True, related_name="state")
    lga = models.ForeignKey(LGA, on_delete=models.SET_NULL, null=True, blank=True, related_name="lga")
    contact_address = models.CharField(max_length=250, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username", "role"]


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
