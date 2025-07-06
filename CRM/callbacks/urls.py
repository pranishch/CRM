from django.urls import path
from . import views

urlpatterns = [
    path('', views.user_login, name='login'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    # Dashboard URLs
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('manager-dashboard/', views.manager_dashboard, name='manager_dashboard'),
    path('managers/manage/', views.manage_managers, name='manage_managers'),
    path('manager-dashboard/<int:manager_id>/', views.manager_dashboard, name='manager_dashboard'),
    # Callback URLs
    path('callbacks/', views.callbacklist, name='callbacklist'),
    path('callbacks/<int:user_id>/', views.callbacklist, name='callbacklist_with_user'),
    path('callbacks/save/', views.save_callbacks, name='save_callbacks'),
    path('callbacks/delete/<int:callback_id>/', views.delete_callback, name='delete_callback'),
    path('callbacks/user/<int:user_id>/', views.view_user_callbacks, name='view_user_callbacks'),
    path('delete-user/<int:user_id>/', views.delete_user, name='delete_user'),
    # User Management URLs
    path('users/manage/', views.manage_users, name='manage_users'),
]