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
def user_logout(request):
    auth.logout(request)
    messages.success(request, 'Logged out successfully.')
    return redirect('login')

@login_required
@never_cache
# @permission_required('auth.manage_users', raise_exception=True)
def admin_dashboard(request):
    if not (request.user.is_superuser or 
            (hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'admin')):
        messages.error(request, 'Access denied. Admin privileges required.')
        return redirect('admin_dashboard')
    
    if not request.user.has_perm('auth.manage_users'):
        messages.error(request, 'Access denied. You lack the required permissions.')
        return redirect('callbacklist')
    
    users = User.objects.all().prefetch_related('userprofile', 'groups')
    total_callbacks = Callback.objects.count()
    total_users = User.objects.count()
    total_managers = User.objects.filter(userprofile__role='manager').count()
    
    context = {
        'users': users,
        'total_callbacks': total_callbacks,
        'total_users': total_users,
        'total_managers': total_managers,
        'user_role': 'admin',
    }
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
    
    context = {
        'manager': manager,
        'agents': agents,
        'available_agents': available_agents,
        'user_role': getattr(request.user.userprofile, 'role', 'agent') if hasattr(request.user, 'userprofile') else 'agent',
    }
    return render(request, 'manager_dashboard.html', context)


@login_required
@csrf_protect
def view_user_callbacks(request, user_id):
    target_user = get_object_or_404(User, id=user_id)
    current_user = request.user
    
    # Restrict access to only the logged-in user's callbacks unless admin or manager
    if current_user != target_user and not (current_user.is_superuser or (hasattr(current_user, 'userprofile') and current_user.userprofile.role in ['admin', 'manager'])):
        messages.error(request, 'Access denied. You can only view your own callbacks.')
        return redirect('callbacklist')
    
    # Get search parameters
    search_query = request.GET.get('q', '').strip()
    search_field = request.GET.get('search_field', 'customer_name')

    if current_user.is_superuser or (hasattr(current_user, 'userprofile') and current_user.userprofile.role == 'admin'):
        callbacks = Callback.objects.filter(created_by=target_user).order_by('-added_at')
        can_edit = True
    elif hasattr(current_user, 'userprofile') and current_user.userprofile.role == 'manager':
        if hasattr(target_user, 'userprofile') and target_user.userprofile.role != 'agent':
            messages.error(request, 'Access denied.')
            return redirect('manager_dashboard', manager_id=current_user.id)
        if target_user.userprofile.manager != current_user:
            messages.error(request, 'Access denied. You can only view callbacks of your assigned agents.')
            return redirect('manager_dashboard', manager_id=current_user.id)
        callbacks = Callback.objects.filter(created_by=target_user).order_by('-added_at')
        can_edit = False
    else:
        if current_user != target_user:
            messages.error(request, 'Access denied.')
            return redirect('callbacklist')
        callbacks = Callback.objects.filter(created_by=current_user).order_by('-added_at')
        can_edit = True
    
    # Apply search filter
    if search_query:
        if search_field == 'all':
            callbacks = callbacks.filter(
                Q(customer_name__icontains=search_query) |
                Q(phone_number__icontains=search_query) |
                Q(address__icontains=search_query) |
                Q(website__icontains=search_query) |
                Q(remarks__icontains=search_query) |
                Q(notes__icontains=search_query)
            )
        elif search_field == 'customer_name':
            callbacks = callbacks.filter(customer_name__icontains=search_query)
        elif search_field == 'phone_number':
            callbacks = callbacks.filter(phone_number__icontains=search_query)

    # Add pagination
    paginator = Paginator(callbacks, 20)  # Show 20 callbacks per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'callbacks': page_obj.object_list,
        'page_obj': page_obj,
        'target_user': target_user,
        'can_edit': can_edit,
        'is_viewing_other': current_user != target_user,
        'user_role': getattr(current_user.userprofile, 'role', 'agent') if hasattr(current_user, 'userprofile') else 'agent',
        'search_query': search_query,
        'search_field': search_field,
    }
    return render(request, 'view_user_callbacklist.html', context)

@login_required
@csrf_protect
def callbacklist(request, user_id=None):
    # Determine user role and permissions
    user_role = get_user_role(request.user)
    can_manage = can_manage_users(request.user)
    can_edit_all = can_edit_all_callbacks(request.user)
    can_delete = can_edit_all  # Assuming delete permission aligns with edit_all
    # Get search parameters
    search_query = request.GET.get('q', '').strip()
    search_field = request.GET.get('search_field', 'customer_name')  # Default to customer_name

    # Initialize context
    context = {
        'user_role': user_role,
        'can_manage_users': can_manage,
        'can_edit_all': can_edit_all,
        'can_delete': can_delete,
        'search_query': search_query,
        'search_field': search_field,
    }

    if user_id:
        # User-specific callbacks
        target_user = get_object_or_404(User, id=user_id)
        # Restrict access to only the logged-in user's callbacks unless admin or manager
        if request.user != target_user and not (request.user.is_superuser or (hasattr(request.user, 'userprofile') and request.user.userprofile.role in ['admin', 'manager'])):
            messages.error(request, 'Access denied. You can only view your own callbacks.')
            return redirect('callbacklist')  # Redirect to the logged-in user's callback list
        # Filter callbacks where the user is either the creator or assigned
        callbacks = Callback.objects.filter(created_by=target_user).order_by('-added_at')
        context.update({
            'is_viewing_other': True,
            'target_user': target_user,
        })
    else:
        # General callback list
        if user_role == 'agent':
            # Agents see only their own callbacks
            callbacks = Callback.objects.filter(created_by=request.user).order_by('-added_at')
        else:
            # Admins and managers see all callbacks
            callbacks = Callback.objects.all().order_by('-added_at')
        context.update({
            'is_viewing_other': False,
        })

    # Apply search filter
    if search_query:
        if search_field == 'all':
            callbacks = callbacks.filter(
                Q(customer_name__icontains=search_query) |
                Q(phone_number__icontains=search_query) |
                Q(address__icontains=search_query) |
                Q(website__icontains=search_query) |
                Q(remarks__icontains=search_query) |
                Q(notes__icontains=search_query)
            )
        elif search_field == 'customer_name':
            callbacks = callbacks.filter(customer_name__icontains=search_query)
        elif search_field == 'phone_number':
            callbacks = callbacks.filter(phone_number__icontains=search_query)
       

    # Add pagination
    paginator = Paginator(callbacks, 20)  # Show 20 callbacks per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context.update({
        'page_obj': page_obj,
        'callbacks': page_obj.object_list,  # Pass the paginated list
    })

    return render(request, 'callbacklist.html', context)

@login_required
@csrf_protect
def save_callbacks(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)
    
    try:
        user = request.user
        saved_count = 0
        
        can_edit_all = user.is_superuser or (hasattr(user, 'userprofile') and user.userprofile.role == 'admin')
        
        target_user_id = request.POST.get('target_user_id')
        if target_user_id and can_edit_all:
            target_user = get_object_or_404(User, id=target_user_id)
            Callback.objects.filter(created_by=target_user).delete()
            callback_owner = target_user
        else:
            if can_edit_all:
                existing_callbacks = Callback.objects.all()
            else:
                existing_callbacks = Callback.objects.filter(created_by=user)
            existing_callbacks.delete()
            callback_owner = user
        
        for i, name in enumerate(request.POST.getlist('customer_name')):
            name = name.strip()
            phone_list = request.POST.getlist('phone_number')
            phone = phone_list[i].strip() if i < len(phone_list) else ''
            
            if not name and not phone:
                continue
            
            if not re.match(r'^[A-Za-z\s]+$', name):
                raise ValidationError("Customer name can only contain letters and spaces")
            if len(name) < 2:
                raise ValidationError("Customer name must be at least 2 characters")
            if not re.match(r'^[\+\-0-9\s]+$', phone):
                raise ValidationError("Phone number can only contain numbers, +, - and spaces")
            if len(phone) < 5:
                raise ValidationError("Phone number must be at least 5 characters")
            
            address_list = request.POST.getlist('address')
            remarks_list = request.POST.getlist('remarks')
            website_list = request.POST.getlist('website')
            notes_list = request.POST.getlist('notes')
            is_completed_list = request.POST.getlist('is_completed')
            
            address = address_list[i].strip() if i < len(address_list) else ''
            remarks = remarks_list[i].strip() if i < len(remarks_list) else ''
            website = website_list[i].strip() if i < len(website_list) else ''
            notes = notes_list[i].strip() if i < len(notes_list) else ''
            is_completed = str(i) in is_completed_list
            
            if address and len(address) < 5:
                raise ValidationError("Address must be at least 5 characters if provided")
            if website and not re.match(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', website):
                raise ValidationError("Website must be a valid URL (e.g., http://example.com)")
            if website and len(website) > 255:
                raise ValidationError("Website URL must not exceed 255 characters")
            if notes and len(notes) > 255:
                raise ValidationError("Notes must not exceed 255 characters")
            
            added_at_list = request.POST.getlist('added_at')
            added_at = added_at_list[i].strip() if i < len(added_at_list) and added_at_list[i].strip() else None
            try:
                if added_at:
                    added_at = datetime.strptime(added_at, '%Y-%m-%d %H:%M:%S')
                else:
                    added_at = datetime.now()
            except (ValueError, TypeError):
                added_at = datetime.now()
            
            Callback.objects.create(
                customer_name=name,
                address=address,
                phone_number=phone,
                website=website,
                remarks=remarks,
                notes=notes,
                is_completed=is_completed,
                created_by=callback_owner,
                added_at=added_at
            )
            saved_count += 1
        
        # If it's an AJAX request, return JSON
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({
                'status': 'success',
                'message': f'Saved {saved_count} entries',
                'saved_count': saved_count
            })
        # Otherwise, redirect with a success message
        else:
            messages.success(request, f'Saved {saved_count} entries')
            if target_user_id and can_edit_all:
                return redirect('view_user_callbacks', user_id=target_user_id)
            else:
                return redirect('callbacklist')
        
    except ValidationError as e:
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
        else:
            messages.error(request, str(e))
            if target_user_id and can_edit_all:
                return redirect('view_user_callbacks', user_id=target_user_id)
            else:
                return redirect('callbacklist')
    except Exception as e:
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': 'error', 'message': f'Error: {str(e)}'}, status=400)
        else:
            messages.error(request, f'Error: {str(e)}')
            if target_user_id and can_edit_all:
                return redirect('view_user_callbacks', user_id=target_user_id)
            else:
                return redirect('callbacklist')

@login_required
@csrf_protect
@never_cache
def delete_callback(request, callback_id):
    if not request.user.is_superuser:
        messages.error(request, 'Access denied. Only superusers can delete callbacks.')
        return redirect('callbacklist')
    
    callback = get_object_or_404(Callback, id=callback_id)
    user_id = callback.created_by.id  # Get the user_id from the callback's created_by field
    callback.delete()
    messages.success(request, 'Callback deleted successfully.')
    return redirect('callbacklist_with_user', user_id=user_id)

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


