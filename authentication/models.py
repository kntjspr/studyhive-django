from django.db import models
from django.contrib.auth.models import User

class PendingRegistration(models.Model):
    """
    Model to store temporary registration data before OTP verification
    """
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=128)
    first_name = models.CharField(max_length=150, default="")
    last_name = models.CharField(max_length=150, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email
        
    class Meta:
        verbose_name = "Pending Registration"
        verbose_name_plural = "Pending Registrations" 