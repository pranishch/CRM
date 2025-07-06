# from django.shortcuts import redirect
# from django.urls import reverse

# class RedirectAuthenticatedUserMiddleware:
#     def __init__(self, get_response):   
#         self.get_response = get_response

#     def __call__(self, request):
#         # Check if the user is authenticated and trying to access the login page
#         if request.user.is_authenticated and request.path == reverse('login'):
#             # Redirect based on user role
#             if request.user.is_superuser or (hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'admin'):
#                 return redirect('admin_dashboard')
#             elif hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'manager':
#                 return redirect('manager_dashboard', manager_id=request.user.id)
#             else:
#                 return redirect('callbacklist')
#         return self.get_response(request)