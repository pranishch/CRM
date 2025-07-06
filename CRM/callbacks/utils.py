from django.contrib.auth.models import User
from .models import UserProfile

def get_user_role(user):
    """
    Returns the role of the user based on their UserProfile.
    """
    try:    
        profile = UserProfile.objects.get(user=user)
        return profile.role
    except UserProfile.DoesNotExist:
        return 'agent'  # Default role if UserProfile is missing

def is_admin_user(user):
    """
    Checks if the user is a superuser or has the 'admin' role.
    """
    return user.is_superuser or get_user_role(user) == 'admin'

def can_manage_users(user):
    """
    Checks if the user has permission to manage users (admin only).
    """
    return is_admin_user(user)  # Restrict to admins only

def can_edit_all_callbacks(user):
    """
    Checks if the user can edit all callbacks (admin or manager).
    """
    role = get_user_role(user)
    return role in ['admin', 'manager']