import json
import logging
from django.core.paginator import Paginator
from django.contrib import messages, auth
from django.http import JsonResponse, HttpResponseForbidden
from django.core.exceptions import ValidationError, PermissionDenied
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User, Group
from django.db.models import Q
from datetime import datetime
from .models import Callback, UserProfile
from django.contrib.auth import logout
from django.views.decorators.cache import never_cache
from django.db import DatabaseError, transaction
from django.template.loader import render_to_string
from .utils import can_access_manager_dashboard, can_access_user_callbacks, get_user_role, can_manage_users, can_edit_all_callbacks, is_admin_user
import re

from .forms import LoginForm, CustomUserCreationForm  # Import the custom LoginForm

@csrf_protect
@never_cache
def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request, request.POST)
        if form.is_valid():
            user = form.get_user()
            if user.is_active:
                auth.login(request, user)
                try:
                    user_role = user.userprofile.role
                    if user_role == 'admin' or user.is_superuser:
                        return redirect('admin_dashboard')
                    elif user_role == 'manager':
                        return redirect('manager_dashboard', manager_id=user.id)
                    else:  # agent
                        return redirect('callbacklist')
                except UserProfile.DoesNotExist:
                    if user.is_superuser:
                        return redirect('admin_dashboard')
                    else:
                        return redirect('callbacklist')
            else:
                messages.error(request, 'Your account is inactive. Please contact administrator.')
        else:
            messages.error(request, 'Invalid username/email or password.')
    else:
        form = LoginForm()
    
    # Ensure form fields are empty on GET request
    if request.method == 'GET':
        form.fields['username'].initial = ''
        form.fields['password'].initial = ''
    
    return render(request, 'login.html', {'form': form})

@login_required
@csrf_protect
def manage_users(request):
    if not is_admin_user(request.user):
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('callbacklist')
    
    if request.method == 'POST':
        action = request.POST.get('action')
        user_id = request.POST.get('user_id')
        
        if action == 'create':
            form = CustomUserCreationForm(request.POST)
            if form.is_valid():
                user = form.save()
                role = request.POST.get('role', 'agent')
                UserProfile.objects.create(user=user, role=role)
                try:
                    group = Group.objects.get(name=role.capitalize())
                    user.groups.add(group)
                except Group.DoesNotExist:
                    pass
                messages.success(request, f'User {user.username} created successfully with role {role}!')
            else:
                for error in form.errors.values():
                    messages.error(request, error)
        
        elif action == 'edit':
            user = get_object_or_404(User, id=user_id)
            if user == request.user and not is_admin_user(request.user):
                messages.error(request, 'You cannot edit your own details.')
                return redirect('manage_users')
            username = request.POST.get('username')
            email = request.POST.get('email')
            if username and username != user.username:
                if User.objects.filter(username=username).exclude(id=user_id).exists():
                    messages.error(request, f'Username {username} is already taken.')
                else:
                    user.username = username
            if email != user.email:
                user.email = email if email else ''
            user.save()
            messages.success(request, f'User {user.username} updated successfully!')
        
        elif action == 'change_role':
            user = get_object_or_404(User, id=user_id)
            if user == request.user and not is_admin_user(request.user):
                messages.error(request, 'You cannot change your own role.')
                return redirect('manage_users')
            new_role = request.POST.get('new_role')
            user.groups.clear()
            if new_role in ['agent', 'manager', 'admin']:
                try:
                    group = Group.objects.get(name=new_role.capitalize())
                    user.groups.add(group)
                except Group.DoesNotExist:
                    pass
                profile, created = UserProfile.objects.get_or_create(user=user)
                profile.role = new_role
                profile.save()
                messages.success(request, f'User {user.username} role changed to {new_role}.')
        
        elif action == 'reset_password':
            user = get_object_or_404(User, id=user_id)
            if user == request.user and not is_admin_user(request.user):
                messages.error(request, 'You cannot reset your own password.')
                return redirect('manage_users')
            new_password = request.POST.get('new_password')
            user.set_password(new_password)
            user.save()
            messages.success(request, f'Password reset for {user.username}!')
        
        elif action == 'edit_callback':
            if not is_admin_user(request.user):
                messages.error(request, 'Access denied. Admin privileges required to edit callbacks.')
                return redirect('manage_users')
            callback_id = request.POST.get('callback_id')
            callback = get_object_or_404(Callback, id=callback_id)
            name = request.POST.get('customer_name', '').strip()
            phone = request.POST.get('phone_number', '').strip()
            email = request.POST.get('email', '').strip()
            address = request.POST.get('address', '').strip()
            website = request.POST.get('website', '').strip()
            remarks = request.POST.get('remarks', '').strip()
            notes = request.POST.get('notes', '').strip()
            added_at = request.POST.get('added_at')

            # Validation
            if not name or not phone:
                messages.error(request, 'Customer name and phone number are required.')
                return redirect('manage_users')
            if not re.match(r'^[A-Za-z\s]+$', name):
                messages.error(request, 'Customer name can only contain letters and spaces.')
                return redirect('manage_users')
            if len(name) < 2:
                messages.error(request, 'Customer name must be at least 2 characters.')
                return redirect('manage_users')
            if not re.match(r'^[\+\-0-9\s\(\),./#]+$', phone):
                messages.error(request, 'Phone number can only contain numbers, +, -, (), comma, period, /, #, and spaces.')
                return redirect('manage_users')
            if len(phone) < 5:
                messages.error(request, 'Phone number must be at least 5 characters.')
                return redirect('manage_users')
            if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                messages.error(request, 'Invalid email address.')
                return redirect('manage_users')
            if address and len(address) < 5:
                messages.error(request, 'Address must be at least 5 characters if provided.')
                return redirect('manage_users')
            if website and not re.match(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', website):
                messages.error(request, 'Invalid website URL.')
                return redirect('manage_users')
            if website and len(website) > 255:
                messages.error(request, 'Website URL must not exceed 255 characters.')
                return redirect('manage_users')
            if notes and len(notes) > 255:
                messages.error(request, 'Notes must not exceed 255 characters.')
                return redirect('manage_users')

            try:
                added_at = datetime.strptime(added_at, '%Y-%m-%d %H:%M:%S') if added_at else datetime.now()
            except (ValueError, TypeError):
                added_at = datetime.now()

            callback.customer_name = name
            callback.phone_number = phone
            callback.email = email or None
            callback.address = address or None
            callback.website = website or None
            callback.remarks = remarks or None
            callback.notes = notes or None
            callback.added_at = added_at
            callback.full_clean()
            callback.save()
            messages.success(request, f'Callback {callback.id} updated successfully!')
        
        return redirect('manage_users')
    
    users = User.objects.all().prefetch_related('userprofile', 'groups')
    form = CustomUserCreationForm()
    callbacks = Callback.objects.filter(created_by__in=users).order_by('-added_at')
    
    context = {
        'users': users,
        'roles': ['agent', 'manager', 'admin'],
        'form': form,
        'user_role': 'admin',
        'callbacks': callbacks,
    }
    return render(request, 'manage_users.html', context)

@login_required
@csrf_protect
def manage_managers(request):
    if not is_admin_user(request.user):
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('callbacklist')
    
    if request.method == 'POST':
        action = request.POST.get('action')
        user_id = request.POST.get('user_id')
        
        if action == 'create':
            form = CustomUserCreationForm(request.POST)
            if form.is_valid():
                user = form.save()
                role = request.POST.get('role', 'manager')
                UserProfile.objects.create(user=user, role=role)
                try:
                    group = Group.objects.get(name=role.capitalize())
                    user.groups.add(group)
                except Group.DoesNotExist:
                    pass
                messages.success(request, f'Manager {user.username} created successfully!')
            else:
                for error in form.errors.values():
                    messages.error(request, error)
        
        elif action == 'edit':
            user = get_object_or_404(User, id=user_id)
            if user == request.user and not is_admin_user(request.user):
                messages.error(request, 'You cannot edit your own details.')
                return redirect('manage_managers')
            username = request.POST.get('username')
            email = request.POST.get('email')
            if username and username != user.username:
                if User.objects.filter(username=username).exclude(id=user_id).exists():
                    messages.error(request, f'Username {username} is already taken.')
                else:
                    user.username = username
            if email != user.email:
                user.email = email if email else ''
            user.save()
            messages.success(request, f'Manager {user.username} updated successfully!')
        
        elif action == 'change_role':
            user = get_object_or_404(User, id=user_id)
            if user == request.user and not is_admin_user(request.user):
                messages.error(request, 'You cannot change your own role.')
                return redirect('manage_managers')
            new_role = request.POST.get('new_role')
            user.groups.clear()
            if new_role in ['agent', 'manager', 'admin']:
                try:
                    group = Group.objects.get(name=new_role.capitalize())
                    user.groups.add(group)
                except Group.DoesNotExist:
                    pass
                profile, created = UserProfile.objects.get_or_create(user=user)
                profile.role = new_role
                profile.save()
                messages.success(request, f'Manager {user.username} role changed to {new_role}.')
        
        elif action == 'reset_password':
            user = get_object_or_404(User, id=user_id)
            if user == request.user and not is_admin_user(request.user):
                messages.error(request, 'You cannot reset your own password.')
                return redirect('manage_managers')
            new_password = request.POST.get('new_password')
            user.set_password(new_password)
            user.save()
            messages.success(request, f'Password reset for {user.username}!')
        
        elif action == 'edit_callback':
            if not is_admin_user(request.user):
                messages.error(request, 'Access denied. Admin privileges required to edit callbacks.')
                return redirect('manage_managers')
            callback_id = request.POST.get('callback_id')
            callback = get_object_or_404(Callback, id=callback_id)
            name = request.POST.get('customer_name', '').strip()
            phone = request.POST.get('phone_number', '').strip()
            email = request.POST.get('email', '').strip()
            address = request.POST.get('address', '').strip()
            website = request.POST.get('website', '').strip()
            remarks = request.POST.get('remarks', '').strip()
            notes = request.POST.get('notes', '').strip()
            added_at = request.POST.get('added_at')

            # Validation
            if not name or not phone:
                messages.error(request, 'Customer name and phone number are required.')
                return redirect('manage_managers')
            if not re.match(r'^[A-Za-z\s]+$', name):
                messages.error(request, 'Customer name can only contain letters and spaces.')
                return redirect('manage_managers')
            if len(name) < 2:
                messages.error(request, 'Customer name must be at least 2 characters.')
                return redirect('manage_managers')
            if not re.match(r'^[\+\-0-9\s\(\),./#]+$', phone):
                messages.error(request, 'Phone number can only contain numbers, +, -, (), comma, period, /, #, and spaces.')
                return redirect('manage_managers')
            if len(phone) < 5:
                messages.error(request, 'Phone number must be at least 5 characters.')
                return redirect('manage_managers')
            if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                messages.error(request, 'Invalid email address.')
                return redirect('manage_managers')
            if address and len(address) < 5:
                messages.error(request, 'Address must be at least 5 characters if provided.')
                return redirect('manage_managers')
            if website and not re.match(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', website):
                messages.error(request, 'Invalid website URL.')
                return redirect('manage_managers')
            if website and len(website) > 255:
                messages.error(request, 'Website URL must not exceed 255 characters.')
                return redirect('manage_managers')
            if notes and len(notes) > 255:
                messages.error(request, 'Notes must not exceed 255 characters.')
                return redirect('manage_managers')

            try:
                added_at = datetime.strptime(added_at, '%Y-%m-%d %H:%M:%S') if added_at else datetime.now()
            except (ValueError, TypeError):
                added_at = datetime.now()

            callback.customer_name = name
            callback.phone_number = phone
            callback.email = email or None
            callback.address = address or None
            callback.website = website or None
            callback.remarks = remarks or None
            callback.notes = notes or None
            callback.added_at = added_at
            callback.full_clean()
            callback.save()
            messages.success(request, f'Callback {callback.id} updated successfully!')
        
        return redirect('manage_managers')
    
    managers = User.objects.filter(userprofile__role='manager').prefetch_related('userprofile', 'groups')
    form = CustomUserCreationForm()
    callbacks = Callback.objects.filter(created_by__in=managers).order_by('-added_at')
    
    context = {
        'managers': managers,
        'roles': ['agent', 'manager', 'admin'],
        'form': form,
        'user_role': 'admin',
        'callbacks': callbacks,
    }
    return render(request, 'manage_managers.html', context)


@csrf_protect
@never_cache
def user_logout(request):
    logout(request)
    return redirect('login')

@login_required
@never_cache
def admin_dashboard(request):
    if not is_admin_user(request.user):
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('callbacklist')
    
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'edit_callback':
            if not is_admin_user(request.user):
                messages.error(request, 'Access denied. Admin privileges required to edit callbacks.')
                return redirect('admin_dashboard')
            callback_id = request.POST.get('callback_id')
            callback = get_object_or_404(Callback, id=callback_id)
            name = request.POST.get('customer_name', '').strip()
            phone = request.POST.get('phone_number', '').strip()
            email = request.POST.get('email', '').strip()
            address = request.POST.get('address', '').strip()
            website = request.POST.get('website', '').strip()
            remarks = request.POST.get('remarks', '').strip()
            notes = request.POST.get('notes', '').strip()
            added_at = request.POST.get('added_at')

            # Validation
            if not name or not phone:
                messages.error(request, 'Customer name and phone number are required.')
                return redirect('admin_dashboard')
            if not re.match(r'^[A-Za-z\s]+$', name):
                messages.error(request, 'Customer name can only contain letters and spaces.')
                return redirect('admin_dashboard')
            if len(name) < 2:
                messages.error(request, 'Customer name must be at least 2 characters.')
                return redirect('admin_dashboard')
            if not re.match(r'^[\+\-0-9\s\(\),./#]+$', phone):
                messages.error(request, 'Phone number can only contain numbers, +, -, (), comma, period, /, #, and spaces.')
                return redirect('admin_dashboard')
            if len(phone) < 5:
                messages.error(request, 'Phone number must be at least 5 characters.')
                return redirect('admin_dashboard')
            if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                messages.error(request, 'Invalid email address.')
                return redirect('admin_dashboard')
            if address and len(address) < 5:
                messages.error(request, 'Address must be at least 5 characters if provided.')
                return redirect('admin_dashboard')
            if website and not re.match(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', website):
                messages.error(request, 'Invalid website URL.')
                return redirect('admin_dashboard')
            if website and len(website) > 255:
                messages.error(request, 'Website URL must not exceed 255 characters.')
                return redirect('admin_dashboard')
            if notes and len(notes) > 255:
                messages.error(request, 'Notes must not exceed 255 characters.')
                return redirect('admin_dashboard')

            try:
                added_at = datetime.strptime(added_at, '%Y-%m-%d %H:%M:%S') if added_at else datetime.now()
            except (ValueError, TypeError):
                added_at = datetime.now()

            callback.customer_name = name
            callback.phone_number = phone
            callback.email = email or None
            callback.address = address or None
            callback.website = website or None
            callback.remarks = remarks or None
            callback.notes = notes or None
            callback.added_at = added_at
            callback.full_clean()
            callback.save()
            messages.success(request, f'Callback {callback.id} updated successfully!')
            return redirect('admin_dashboard')
    
    search_query = request.GET.get('q', '').strip()
    search_field = request.GET.get('search_field', 'all')

    users = User.objects.all().prefetch_related('userprofile', 'groups')
    total_users = User.objects.count()
    total_managers = User.objects.filter(userprofile__role='manager').count()
    managers = User.objects.filter(userprofile__role='manager').prefetch_related('userprofile', 'groups')
    
    all_callbacks = Callback.objects.all().order_by('-added_at').prefetch_related('created_by__userprofile__manager')
    
    if search_query:
        try:
            if search_field == 'all':
                all_callbacks = all_callbacks.filter(
                    Q(customer_name__icontains=search_query) |
                    Q(phone_number__icontains=search_query) |
                    Q(email__icontains=search_query) |
                    Q(address__icontains=search_query) |
                    Q(website__icontains=search_query) |
                    Q(remarks__icontains=search_query) |
                    Q(notes__icontains=search_query)
                )
            elif search_field == 'customer_name':
                all_callbacks = all_callbacks.filter(customer_name__icontains=search_query)
            elif search_field == 'phone_number':
                all_callbacks = all_callbacks.filter(phone_number__icontains=search_query)
            elif search_field == 'email':
                all_callbacks = all_callbacks.filter(email__icontains=search_query)
        except Exception as e:
            messages.error(request, 'An error occurred while processing the search query.')
            return JsonResponse({'status': 'error', 'message': 'Invalid search query'}, status=400) if request.headers.get('X-Requested-With') == 'XMLHttpRequest' else redirect('admin_dashboard')
    
    total_callbacks = all_callbacks.count()
    
    paginator = Paginator(all_callbacks, 20)
    page_number = request.GET.get('page', 1)
    
    try:
        page_obj = paginator.page(page_number)
    except:
        page_obj = paginator.page(1)  # Fallback to page 1 if invalid page number
    
    context = {
        'users': users,
        'total_callbacks': total_callbacks,
        'total_users': total_users,
        'total_managers': total_managers,
        'all_callbacks': page_obj.object_list,
        'managers': managers,
        'user_role': 'admin',
        'page_obj': page_obj,
        'search_query': search_query,
        'search_field': search_field,
    }
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        try:
            callbacks_html = render_to_string('admin_dashboard_table_body.html', context, request=request)
            pagination_html = render_to_string('admin_dashboard_pagination.html', context, request=request)
            return JsonResponse({
                'status': 'success',
                'callbacks_html': callbacks_html,
                'pagination_html': pagination_html,
                'total_callbacks': total_callbacks
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': 'Error rendering table content'
            }, status=500)
    
    return render(request, 'admin_dashboard.html', context)


@login_required
@csrf_protect
def manager_dashboard(request, manager_id):
    manager = get_object_or_404(User, id=manager_id)
    # Use the new access control function
    if not can_access_manager_dashboard(request.user, manager):
        messages.error(request, 'Access denied. You can only view your own dashboard.')
        return redirect('callbacklist')
    
    if request.method == 'POST':
        if not (request.user.is_superuser or 
                (hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'admin')):
            messages.error(request, 'Access denied. Admin privileges required.')
            return redirect('manager_dashboard', manager_id=manager_id)
        
        action = request.POST.get('action')
        if action == 'assign_agent':
            agent_id = request.POST.get('agent_id')
            agent = get_object_or_404(User, id=agent_id)
            if hasattr(agent, 'userprofile') and agent.userprofile.role != 'agent':
                messages.error(request, 'Only agents can be assigned to managers.')
            else:
                profile, created = UserProfile.objects.get_or_create(user=agent)
                profile.manager = manager
                profile.save()
                messages.success(request, f'Agent {agent.username} assigned to {manager.username}.')
        
        elif action == 'unassign_agent':
            agent_id = request.POST.get('agent_id')
            agent = get_object_or_404(User, id=agent_id)
            profile, created = UserProfile.objects.get_or_create(user=agent)
            profile.manager = None
            profile.save()
            messages.success(request, f'Agent {agent.username} unassigned from {manager.username}.')
        
        return redirect('manager_dashboard', manager_id=manager_id)
    
    agents = User.objects.filter(userprofile__manager=manager, userprofile__role='agent').prefetch_related('userprofile', 'groups')
    available_agents = User.objects.filter(
        Q(userprofile__role='agent') | Q(userprofile__isnull=True)
    ).exclude(userprofile__manager=manager).prefetch_related('userprofile', 'groups')
    
    search_query = request.GET.get('q', '').strip()
    search_field = request.GET.get('search_field', 'all')
    callbacks = Callback.objects.filter(manager=manager).order_by('-added_at')
    
    if search_query:
        if search_field == 'all':
            callbacks = callbacks.filter(
                Q(customer_name__icontains=search_query) |
                Q(phone_number__icontains=search_query) |
                Q(email__icontains=search_query) |
                Q(address__icontains=search_query) |
                Q(website__icontains=search_query) |
                Q(remarks__icontains=search_query) |
                Q(notes__icontains=search_query)
            )
        elif search_field == 'customer_name':
            callbacks = callbacks.filter(customer_name__icontains=search_query)
        elif search_field == 'phone_number':
            callbacks = callbacks.filter(phone_number__icontains=search_query)
        elif search_field == 'email':
            callbacks = callbacks.filter(email__icontains=search_query)
    
    paginator = Paginator(callbacks, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'manager': manager,
        'agents': agents,
        'available_agents': available_agents,
        'user_role': getattr(request.user.userprofile, 'role', 'agent') if hasattr(request.user, 'userprofile') else 'agent',
        'can_edit': request.user.is_superuser or (hasattr(request.user, 'userprofile') and request.user.userprofile.role in ['admin', 'manager']),
        'callbacks': page_obj.object_list,
        'page_obj': page_obj,
        'search_query': search_query,
        'search_field': search_field,
    }
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        callbacks_html = render_to_string('manager_dashboard_callbacks.html', context, request=request)
        pagination_html = render_to_string('manager_dashboard_pagination.html', context, request=request)
        return JsonResponse({
            'callbacks_html': callbacks_html,
            'pagination_html': pagination_html,
        })
    
    return render(request, 'manager_dashboard.html', context)

@login_required
@csrf_protect
def view_user_callbacks(request, user_id):
    target_user = get_object_or_404(User, id=user_id)
    current_user = request.user
    
    if not can_access_user_callbacks(current_user, target_user):
        messages.error(request, 'Access denied. You can only view your own callbacks or those of authorized users.')
        return redirect('callbacklist')
    
    can_edit_all = is_admin_user(current_user)
    can_delete = can_edit_all
    can_edit = can_edit_all or current_user == target_user  # Only admins or the user themselves can edit
    search_query = request.GET.get('q', '').strip()
    search_field = request.GET.get('search_field', 'customer_name')

    if can_edit_all:
        callbacks = Callback.objects.filter(created_by=target_user).order_by('-added_at')
    else:
        if current_user != target_user:
            messages.error(request, 'Access denied.')
            return redirect('callbacklist')
        callbacks = Callback.objects.filter(created_by=current_user).order_by('-added_at')
    
    if search_query:
        if search_field == 'all':
            callbacks = callbacks.filter(
                Q(customer_name__icontains=search_query) |
                Q(phone_number__icontains=search_query) |
                Q(email__icontains=search_query) |
                Q(address__icontains=search_query) |
                Q(website__icontains=search_query) |
                Q(remarks__icontains=search_query) |
                Q(notes__icontains=search_query)
            )
        elif search_field == 'customer_name':
            callbacks = callbacks.filter(customer_name__icontains=search_query)
        elif search_field == 'phone_number':
            callbacks = callbacks.filter(phone_number__icontains=search_query)
        elif search_field == 'email':
            callbacks = callbacks.filter(email__icontains=search_query)

    paginator = Paginator(callbacks, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'callbacks': page_obj.object_list,
        'page_obj': page_obj,
        'target_user': target_user,
        'can_edit': can_edit,
        'can_delete': can_delete,
        'is_viewing_other': current_user != target_user,
        'user_role': get_user_role(current_user),
        'search_query': search_query,
        'search_field': search_field,
    }
    return render(request, 'view_user_callbacklist.html', context)

@login_required
@csrf_protect
def callbacklist(request, user_id=None):
    user_role = get_user_role(request.user)
    can_manage = is_admin_user(request.user)
    can_edit_all = is_admin_user(request.user)
    can_edit = can_edit_all or user_role == 'agent'
    can_delete = can_edit_all
    search_query = request.GET.get('q', '').strip()
    search_field = request.GET.get('search_field', 'customer_name')

    context = {
        'user_role': user_role,
        'can_manage_users': can_manage,
        'can_edit_all': can_edit_all,
        'can_edit': can_edit,
        'can_delete': can_delete,
        'search_query': search_query,
        'search_field': search_field,
    }

    if user_id:
        target_user = get_object_or_404(User, id=user_id)
        if not can_access_user_callbacks(request.user, target_user):
            messages.error(request, 'Access denied. You can only view your own callbacks or those of authorized users.')
            return redirect('callbacklist')
        callbacks = Callback.objects.filter(created_by=target_user)
        context.update({
            'is_viewing_other': True,
            'target_user': target_user,
        })
    else:
        if user_role == 'agent':
            callbacks = Callback.objects.filter(created_by=request.user)
        elif user_role == 'manager':
            callbacks = Callback.objects.filter(manager=request.user)
        else:  # admin
            callbacks = Callback.objects.all()
        context.update({'is_viewing_other': False})

    if search_query:
        try:
            if search_field == 'all':
                callbacks = callbacks.filter(
                    Q(customer_name__icontains=search_query) |
                    Q(phone_number__icontains=search_query) |
                    Q(email__icontains=search_query) |
                    Q(address__icontains=search_query) |
                    Q(website__icontains=search_query) |
                    Q(remarks__icontains=search_query) |
                    Q(notes__icontains=search_query)
                )
            elif search_field == 'customer_name':
                callbacks = callbacks.filter(customer_name__icontains=search_query)
            elif search_field == 'phone_number':
                callbacks = callbacks.filter(phone_number__icontains=search_query)
            elif search_field == 'email':
                callbacks = callbacks.filter(email__icontains=search_query)
        except Exception as e:
            messages.error(request, 'An error occurred while processing the search query.')
            return JsonResponse({'status': 'error', 'message': 'Invalid search query'}, status=400) if request.headers.get('X-Requested-With') == 'XMLHttpRequest' else redirect('callbacklist')

    callbacks = callbacks.order_by('-added_at')
    
    paginator = Paginator(callbacks, 20)
    page_number = request.GET.get('page', 1)
    
    try:
        page_obj = paginator.page(page_number)
    except:
        page_obj = paginator.page(1)  # Fallback to page 1 if invalid page number
    
    context.update({
        'page_obj': page_obj,
        'callbacks': page_obj.object_list,
    })

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        try:
            callbacks_html = render_to_string('callbacklist_table_body.html', context, request=request)
            pagination_html = render_to_string('callbacklist_pagination.html', context, request=request)
            return JsonResponse({
                'status': 'success',
                'callbacks_html': callbacks_html,
                'pagination_html': pagination_html,
                'total_callbacks': callbacks.count()
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': 'Error rendering table content'
            }, status=500)

    return render(request, 'callbacklist.html', context)

logger = logging.getLogger(__name__)
@login_required
@csrf_protect
def save_callbacks(request):
    if request.method != 'POST':
        logger.error("Invalid request method")
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)

    try:
        user = request.user
        user_role = get_user_role(user)
        can_edit_all = is_admin_user(user)

        logger.debug(f"User: {user.username}, Role: {user_role}, Can edit all: {can_edit_all}, POST data: {request.POST}")

        content_type = request.headers.get('Content-Type', '').lower()
        if 'application/json' in content_type:
            data = json.loads(request.body)
            if not isinstance(data, list):
                data = [data]
        else:
            data = [{
                'callback_id': request.POST.get('callback_id'),
                'target_user_id': request.POST.get('target_user_id'),
                'customer_name': request.POST.get('customer_name', '').strip(),
                'phone_number': request.POST.get('phone_number', '').strip(),
                'email': request.POST.get('email', '').strip(),
                'address': request.POST.get('address', '').strip(),
                'website': request.POST.get('website', '').strip(),
                'remarks': request.POST.get('remarks', '').strip(),
                'notes': request.POST.get('notes', '').strip(),
                'added_at': request.POST.get('added_at')
            }]

        saved_count = 0
        saved_callback_ids = []
        with transaction.atomic():
            for callback_data in data:
                callback_id = callback_data.get('callback_id')
                target_user_id = callback_data.get('target_user_id')

                # Determine callback owner
                if target_user_id and can_edit_all:
                    try:
                        callback_owner = User.objects.get(id=target_user_id)
                        if not can_access_user_callbacks(user, callback_owner):
                            logger.error(f"User {user.username} attempted to edit callbacks for unauthorized user {callback_owner.username}")
                            raise PermissionDenied("You are not authorized to edit callbacks for this user")
                    except User.DoesNotExist:
                        logger.error(f"Target user ID {target_user_id} does not exist")
                        raise ValueError(f"Target user ID {target_user_id} does not exist")
                else:
                    callback_owner = user

                name = callback_data.get('customer_name', '').strip()
                phone = callback_data.get('phone_number', '').strip()
                email = callback_data.get('email', '').strip()
                address = callback_data.get('address', '').strip()
                website = callback_data.get('website', '').strip()
                remarks = callback_data.get('remarks', '').strip()
                notes = callback_data.get('notes', '').strip()
                added_at = callback_data.get('added_at')

                # Validation
                if not name or not phone:
                    raise ValueError("Customer name and phone number are required")
                if not re.match(r'^[A-Za-z\s]+$', name):
                    raise ValueError("Customer name can only contain letters and spaces")
                if len(name) < 2:
                    raise ValueError("Customer name must be at least 2 characters")
                if not re.match(r'^[\+\-0-9\s\(\),./#]+$', phone):
                    raise ValueError("Phone number can only contain numbers, +, -, (), comma, period, /, #, and spaces")
                if len(phone) < 5:
                    raise ValueError("Phone number must be at least 5 characters")
                if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                    raise ValueError("Invalid email address")
                if address and len(address) < 5:
                    raise ValueError("Address must be at least 5 characters if provided")
                if website and not re.match(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', website):
                    raise ValueError("Invalid website URL")
                if website and len(website) > 255:
                    raise ValueError("Website URL must not exceed 255 characters")
                if notes and len(notes) > 255:
                    raise ValueError("Notes must not exceed 255 characters")

                try:
                    added_at = datetime.strptime(added_at, '%Y-%m-%d %H:%M:%S') if added_at else datetime.now()
                except (ValueError, TypeError):
                    added_at = datetime.now()

                if callback_id:
                    # Editing existing callback
                    callback = get_object_or_404(Callback, id=callback_id)
                    if not can_edit_all:  # Only apply restrictions for non-admins
                        if user_role == 'manager' and callback.manager != user:
                            logger.error(f"Manager {user.username} attempted to edit unassigned callback {callback_id}")
                            raise PermissionDenied("You can only edit callbacks assigned to you")
                        if user_role == 'agent' and callback.created_by != user:
                            logger.error(f"Agent {user.username} attempted to edit callback {callback_id} not owned by them")
                            raise PermissionDenied("You can only edit your own callbacks")
                    callback.customer_name = name
                    callback.phone_number = phone
                    callback.email = email or None
                    callback.address = address or None
                    callback.website = website or None
                    callback.remarks = remarks or None
                    callback.notes = notes or None
                    callback.added_at = added_at
                    callback.save()
                    logger.info(f"Callback {callback_id} updated by {user.username}")
                    saved_count += 1
                    saved_callback_ids.append(callback.id)
                else:
                    # Creating new callback
                    if user_role not in ['admin', 'agent']:
                        logger.error(f"User {user.username} with role {user_role} attempted to create new callback")
                        raise PermissionDenied("Only admins and agents can create new callbacks")
                    callback = Callback(
                        created_by=callback_owner,
                        manager=None,  # Managers set via assign_manager view
                        added_at=added_at,
                        customer_name=name,
                        phone_number=phone,
                        email=email or None,
                        address=address or None,
                        website=website or None,
                        remarks=remarks or None,
                        notes=notes or None
                    )
                    callback.full_clean()
                    callback.save()
                    logger.info(f"New callback {callback.id} created by {user.username} for user {callback_owner.username}")
                    if not Callback.objects.filter(id=callback.id).exists():
                        logger.error(f"Callback {callback.id} was not saved in the database")
                        raise DatabaseError(f"Callback {callback.id} failed to save")
                    saved_count += 1
                    saved_callback_ids.append(callback.id)

        return JsonResponse({
            'status': 'success',
            'message': f'Successfully saved {saved_count} callback(s).',
            'saved_count': saved_count,
            'callback_ids': saved_callback_ids,
            'target_user_id': target_user_id if can_edit_all else user.id
        })

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    except PermissionDenied as e:
        logger.error(f"Permission denied: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=403)
    except ValidationError as e:
        logger.error(f"Model validation error: {str(e)}")
        return JsonResponse({'status': 'error', 'message': f'Model validation error: {str(e)}'}, status=400)
    except DatabaseError as e:
        logger.error(f"Database error: {str(e)}")
        return JsonResponse({'status': 'error', 'message': f'Database error: {str(e)}'}, status=500)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return JsonResponse({'status': 'error', 'message': f'Error: {str(e)}'}, status=500)

@login_required
@csrf_protect
def delete_callback(request):
    if not is_admin_user(request.user):
        return JsonResponse({'status': 'error', 'message': 'Access denied. Admin privileges required.'}, status=403)
    
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=400)

    try:
        data = json.loads(request.body)
        callback_ids = data.get('callback_ids', [])
        
        if not isinstance(callback_ids, list):
            callback_ids = [callback_ids] if callback_ids else []
        
        if not callback_ids:
            return JsonResponse({'status': 'error', 'message': 'No callbacks selected for deletion.'}, status=400)

        callback_ids = [str(id) for id in callback_ids if id and str(id).isdigit()]
        if not callback_ids:
            return JsonResponse({'status': 'error', 'message': 'Invalid callback IDs provided.'}, status=400)

        deleted_count = Callback.objects.filter(id__in=callback_ids).delete()[0]

        if deleted_count == 0:
            return JsonResponse({'status': 'error', 'message': 'No valid callbacks found for deletion.'}, status=404)
        
        return JsonResponse({
            'status': 'success',
            'message': f'Successfully deleted {deleted_count} callback(s).'
        })
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON data.'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'Error: {str(e)}'}, status=500)
    
@login_required
@csrf_protect
def delete_user(request, user_id):
    if not (request.user.is_superuser or 
            (hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'admin')):
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('manage_users')
    
    user = get_object_or_404(User, id=user_id)
    if user == request.user:
        messages.error(request, 'You cannot delete your own account.')
        return redirect(request.META.get('HTTP_REFERER', 'manage_users'))
    
    username = user.username
    user.delete()
    messages.success(request, f'User {username} deleted successfully.')
    return redirect(request.META.get('HTTP_REFERER', 'manage_users'))

@login_required
@csrf_protect
def assign_manager(request):
    if not is_admin_user(request.user):
        return JsonResponse({'status': 'error', 'message': 'Access denied. Admin privileges required.'}, status=403)
    
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=400)

    try:
        data = json.loads(request.body)
        callback_id = data.get('callback_id')
        manager_id = data.get('manager_id')

        if not callback_id:
            return JsonResponse({'status': 'error', 'message': 'No callback ID provided.'}, status=400)

        callback = get_object_or_404(Callback, id=callback_id)
        
        if manager_id:
            manager = get_object_or_404(User, id=manager_id)
            if hasattr(manager, 'userprofile') and manager.userprofile.role != 'manager':
                return JsonResponse({'status': 'error', 'message': 'Selected user is not a manager.'}, status=400)
            callback.manager = manager
            callback.save()
            return JsonResponse({
                'status': 'success',
                'message': f'Callback assigned to manager {manager.username}.'
            })
        else:
            callback.manager = None
            callback.save()
            return JsonResponse({
                'status': 'success',
                'message': 'Callback unassigned from manager.'
            })

    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON data.'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'Error: {str(e)}'}, status=500)