from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from callbacks.models import Callback

class Command(BaseCommand):
    help = 'Setup user groups and permissions'

    def handle(self, *args, **options):
        try:
            # Get content types
            callback_content_type = ContentType.objects.get_for_model(Callback)
            user_content_type = ContentType.objects.get(app_label='auth', model='user')

            # Create groups
            agent_group, created = Group.objects.get_or_create(name='Agent')
            manager_group, created = Group.objects.get_or_create(name='Manager')
            admin_group, created = Group.objects.get_or_create(name='Admin')

            # Define permissions with their respective content types
            permissions = {
                'Agent': [
                    ('add_callback', callback_content_type),
                    ('view_callback', callback_content_type),
                    ('change_callback', callback_content_type),
                ],
                'Manager': [
                    ('view_callback', callback_content_type),
                    ('view_all_callbacks', callback_content_type),
                    ('edit_all_callbacks', callback_content_type),
                ],
                'Admin': [
                    ('add_callback', callback_content_type),
                    ('view_callback', callback_content_type),
                    ('change_callback', callback_content_type),
                    ('delete_callback', callback_content_type),
                    ('view_all_callbacks', callback_content_type),
                    ('edit_all_callbacks', callback_content_type),
                    ('delete_all_callbacks', callback_content_type),
                    ('manage_users', user_content_type),
                    ('manage_managers', user_content_type),
                ],
            }

            # Assign permissions to groups
            for group_name, perm_list in permissions.items():
                group = Group.objects.get(name=group_name)
                group.permissions.clear()  # Clear existing permissions to avoid duplicates
                for perm_name, content_type in perm_list:
                    try:
                        permission = Permission.objects.get(codename=perm_name, content_type=content_type)
                        group.permissions.add(permission)
                        self.stdout.write(self.style.SUCCESS(f"Added permission {perm_name} to {group_name}"))
                    except Permission.DoesNotExist:
                        self.stdout.write(self.style.WARNING(f"Permission {perm_name} not found for {content_type}"))

            self.stdout.write(self.style.SUCCESS('Successfully set up groups and permissions'))

        except ContentType.DoesNotExist as e:
            self.stdout.write(self.style.ERROR(f'ContentType not found: {str(e)}. Ensure migrations are applied.'))