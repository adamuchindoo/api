# user/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User


@receiver(post_save, sender=User)
def create_related_profiles(sender, instance, created, **kwargs):
    if created:
        # Example: Auto-create MSME profile if role is 'msme'
        if instance.role == "msme":
            pass  # from msme.models import MSMERegistration; MSMERegistration.objects.create(user=instance)
