from django.db import models
from django.contrib.auth.models import User

class Callback(models.Model):
    customer_name = models.CharField(max_length=100, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    website = models.URLField(max_length=255, blank=True, null=True)
    remarks = models.TextField(blank=True, null=True)
    notes = models.TextField(max_length=255, blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='callbacks_created', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True,blank=True, null=True)
    is_completed = models.BooleanField(default=False)

    class Meta:
        permissions = [
            ('view_all_callbacks', 'Can view all callbacks'),
            ('edit_all_callbacks', 'Can edit all callbacks'),
            ('delete_all_callbacks', 'Can delete all callbacks'),
            ('manage_users', 'Can manage users'),
        ]
        indexes = [
            models.Index(fields=['created_by', 'created_at']),
        ]

    def __str__(self):
        return self.customer_name or "Unnamed Customer"

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=[
        ('agent', 'Agent'),
        ('manager', 'Manager'),
        ('admin', 'Admin')
    ], default='Agent')
    manager = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='managed_agents')

    def __str__(self):
        return f"{self.user.username} - {self.role}"