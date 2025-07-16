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

def can_access_user_callbacks(current_user, target_user):
    """
    Check if the current user can access the target user's callbacks.
    Returns True if allowed, False otherwise.
    """
    if not current_user.is_authenticated:
        return False
    
    # Superusers and admins can access any user's callbacks
    if current_user.is_superuser or (hasattr(current_user, 'userprofile') and current_user.userprofile.role == 'admin'):
        return True
    
    # Current user can access their own callbacks only
    if current_user == target_user:
        return True
    
    # No other access allowed (managers cannot access agents' callbacks, agents cannot access managers' callbacks)
    return False

def can_access_manager_dashboard(current_user, manager):
    """
    Check if the current user can access the manager's dashboard.
    Returns True if allowed, False otherwise.
    """
    if not current_user.is_authenticated:
        return False
    
    # Superusers and admins can access any manager's dashboard
    if current_user.is_superuser or (hasattr(current_user, 'userprofile') and current_user.userprofile.role == 'admin'):
        return True
    
    # Current user can access their own dashboard
    if current_user == manager:
        return True
    
    return False