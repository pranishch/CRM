import json
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
from django.views.decorators.cache import never_cache
from django.template.loader import render_to_string
from .utils import get_user_role, can_manage_users, can_edit_all_callbacks
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
    if not (request.user.is_superuser or 
            (hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'admin')):
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
            new_password = request.POST.get('new_password')
            user.set_password(new_password)
            user.save()
            messages.success(request, f'Password reset for {user.username}!')
        
        return redirect('manage_users')
    
    users = User.objects.all().prefetch_related('userprofile', 'groups')
    form = CustomUserCreationForm()
    
    context = {
        'users': users,
        'roles': ['agent', 'manager', 'admin'],
        'form': form,
        'user_role': 'admin',
    }
    return render(request, 'manage_users.html', context)

@login_required
@csrf_protect
def manage_managers(request):
    if not (request.user.is_superuser or 
            (hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'admin')):
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
            new_password = request.POST.get('new_password')
            user.set_password(new_password)
            user.save()
            messages.success(request, f'Password reset for {user.username}!')
        
        return redirect('manage_managers')
    
    managers = User.objects.filter(userprofile__role='manager').prefetch_related('userprofile', 'groups')
    form = CustomUserCreationForm()
    
    context = {
        'managers': managers,
        'roles': ['agent', 'manager', 'admin'],
        'form': form,
        'user_role': 'admin',
    }
    return render(request, 'manage_managers.html', context)

@login_required
@csrf_protect
def user_logout(request):
    auth.logout(request)
    messages.success(request, 'Logged out successfully.')
    return redirect('login')

@login_required
@never_cache
def admin_dashboard(request):
    if not (request.user.is_superuser or 
            (hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'admin')):
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('callbacklist')
    
    if not request.user.has_perm('auth.manage_users'):
        messages.error(request, 'Access denied. You lack the required permissions.')
        return redirect('callbacklist')
    
    search_query = request.GET.get('q', '').strip()
    search_field = request.GET.get('search_field', 'all')

    users = User.objects.all().prefetch_related('userprofile', 'groups')
    total_users = User.objects.count()
    total_managers = User.objects.filter(userprofile__role='manager').count()
    managers = User.objects.filter(userprofile__role='manager').prefetch_related('userprofile', 'groups')
    
    all_callbacks = Callback.objects.all().order_by('-added_at').prefetch_related('created_by__userprofile__manager')
    
    if search_query:
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
    
    total_callbacks = all_callbacks.count()
    
    paginator = Paginator(all_callbacks, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
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
        callbacks_html = render_to_string('admin_dashboard_table_body.html', context, request=request)
        pagination_html = render_to_string('admin_dashboard_pagination.html', context, request=request)
        return JsonResponse({
            'callbacks_html': callbacks_html,
            'pagination_html': pagination_html,
            'total_callbacks': total_callbacks
        })
    
    return render(request, 'admin_dashboard.html', context)

@login_required
@csrf_protect
def manager_dashboard(request, manager_id):
    manager = get_object_or_404(User, id=manager_id)
    if not (request.user.is_superuser or 
            (hasattr(request.user, 'userprofile') and request.user.userprofile.role in ['admin', 'manager'])):
        messages.error(request, 'Access denied.')
        return redirect('callbacklist')
    
    if request.user.userprofile.role == 'manager' and request.user != manager:
        messages.error(request, 'Access denied. You can only view your own dashboard.')
        return redirect('manager_dashboard', manager_id=request.user.id)
    
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
    
    if current_user != target_user and not (current_user.is_superuser or (hasattr(current_user, 'userprofile') and current_user.userprofile.role in ['admin', 'manager'])):
        messages.error(request, 'Access denied. You can only view your own callbacks.')
        return redirect('callbacklist')
    
    can_edit_all = can_edit_all_callbacks(current_user)
    can_delete = can_edit_all
    can_edit = can_edit_all or current_user == target_user or get_user_role(current_user) == 'manager'
    search_query = request.GET.get('q', '').strip()
    search_field = request.GET.get('search_field', 'customer_name')

    if can_edit_all:
        callbacks = Callback.objects.filter(created_by=target_user).order_by('-added_at')
    elif hasattr(current_user, 'userprofile') and current_user.userprofile.role == 'manager':
        if hasattr(target_user, 'userprofile') and target_user.userprofile.role != 'agent':
            messages.error(request, 'Access denied.')
            return redirect('manager_dashboard', manager_id=current_user.id)
        if target_user.userprofile.manager != current_user:
            messages.error(request, 'Access denied. You can only view callbacks of your assigned agents.')
            return redirect('manager_dashboard', manager_id=current_user.id)
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
    can_manage = can_manage_users(request.user)
    can_edit_all = can_edit_all_callbacks(request.user)
    can_edit = user_role in ['admin', 'agent', 'manager']
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
        if request.user != target_user and not (request.user.is_superuser or user_role in ['admin', 'manager']):
            messages.error(request, 'Access denied. You can only view your own callbacks.')
            return redirect('callbacklist')
        callbacks = Callback.objects.filter(created_by=target_user)
        context.update({
            'is_viewing_other': True,
            'target_user': target_user,
        })
    else:
        if user_role == 'agent':
            callbacks = Callback.objects.filter(created_by=request.user)
        else:
            callbacks = Callback.objects.all()
        context.update({'is_viewing_other': False})

    # Apply search filters if they exist
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

    # Consistent ordering
    callbacks = callbacks.order_by('-added_at')
    
    # Pagination
    paginator = Paginator(callbacks, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context.update({
        'page_obj': page_obj,
        'callbacks': page_obj.object_list,
    })

    # Handle AJAX request for search
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        from django.template.loader import render_to_string
        callbacks_html = render_to_string('callbacklist_table_body.html', context, request=request)
        pagination_html = render_to_string('callbacklist_pagination.html', context, request=request)
        return JsonResponse({
            'callbacks_html': callbacks_html,
            'pagination_html': pagination_html
        })

    return render(request, 'callbacklist.html', context)

@login_required
@csrf_protect
def save_callbacks(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)

    try:
        user = request.user
        user_role = get_user_role(user)
        can_edit_all = can_edit_all_callbacks(user)

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
        for callback_data in data:
            callback_id = callback_data.get('callback_id')
            target_user_id = callback_data.get('target_user_id')
            if target_user_id and not can_edit_all:
                return JsonResponse({'status': 'error', 'message': 'Permission denied'}, status=403)
            
            callback_owner = get_object_or_404(User, id=target_user_id) if target_user_id and can_edit_all else user

            name = callback_data.get('customer_name', '').strip()
            phone = callback_data.get('phone_number', '').strip()
            email = callback_data.get('email', '').strip()
            address = callback_data.get('address', '').strip()
            website = callback_data.get('website', '').strip()
            remarks = callback_data.get('remarks', '').strip()
            notes = callback_data.get('notes', '').strip()
            added_at = callback_data.get('added_at')

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
                callback = get_object_or_404(Callback, id=callback_id)
                if user_role == 'manager' and callback.manager != user:
                    raise PermissionDenied("You can only edit callbacks assigned to you")
                callback.customer_name = name
                callback.phone_number = phone
                callback.email = email
                callback.address = address
                callback.website = website
                callback.remarks = remarks
                callback.notes = notes
                callback.added_at = added_at
                callback.save()
                saved_count += 1
            else:
                if user_role not in ['admin', 'agent']:
                    raise ValueError("Only admins and agents can create new callbacks")
                callback = Callback.objects.create(
                    created_by=callback_owner,
                    added_at=added_at,
                    customer_name=name,
                    phone_number=phone,
                    email=email,
                    address=address,
                    website=website,
                    remarks=remarks,
                    notes=notes
                )
                saved_count += 1

        return JsonResponse({
            'status': 'success',
            'message': f'Successfully saved {saved_count} callback(s).',
            'saved_count': saved_count
        })

    except ValueError as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    except PermissionDenied as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=403)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'Error: {str(e)}'}, status=400)
    
@login_required
@csrf_protect
def delete_callback(request):
    if not (request.user.is_superuser or 
            (hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'admin')):
        return JsonResponse({'status': 'error', 'message': 'Access denied. Admin privileges required.'}, status=403)
    
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=400)

    try:
        # Expect JSON payload with callback_ids
        data = json.loads(request.body)
        callback_ids = data.get('callback_ids', [])
        
        # Ensure callback_ids is a list
        if not isinstance(callback_ids, list):
            callback_ids = [callback_ids] if callback_ids else []
        
        if not callback_ids:
            return JsonResponse({'status': 'error', 'message': 'No callbacks selected for deletion.'}, status=400)

        # Ensure all IDs are valid integers
        callback_ids = [str(id) for id in callback_ids if id and str(id).isdigit()]
        if not callback_ids:
            return JsonResponse({'status': 'error', 'message': 'Invalid callback IDs provided.'}, status=400)

        # Delete callbacks (admin can delete any callback)
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
    if not (request.user.is_superuser or 
            (hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'admin')):
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
    
