from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from callbacks.models import UserProfile, Callback

class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = True
    verbose_name_plural = 'User Profiles'
    fk_name = 'user'  # Specify the ForeignKey to use

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'manager']  # Removed 'department' and 'phone'
    list_filter = ['role']
    search_fields = ['user__username', 'user__email']

class CustomUserAdmin(UserAdmin):
    inlines = [UserProfileInline]
    list_display = ['username', 'email', 'first_name', 'last_name', 'get_role', 'is_active', 'is_superuser']
    list_filter = ['is_active', 'is_superuser', 'userprofile__role']  # Add role filter

    def get_role(self, obj):
        try:
            return obj.userprofile.role
        except UserProfile.DoesNotExist:
            return 'No role'
    get_role.short_description = 'Role'

class CallbackAdmin(admin.ModelAdmin):
    list_display = ['customer_name', 'phone_number', 'created_by', 'created_at', 'is_completed']
    list_filter = ['is_completed', 'created_at', 'created_by']
    search_fields = ['customer_name', 'phone_number', 'address', 'remarks']
    readonly_fields = ['created_at']
    list_editable = ['is_completed']  # Allow toggling is_completed in list view

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
admin.site.register(UserProfile, UserProfileAdmin)
admin.site.register(Callback, CallbackAdmin)