"""URL configuration for studyhive project."""

from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse

def health_check(request):
    """Health check endpoint"""
    return JsonResponse({
        "status": "success",
        "message": "Server is healthy",
    })

urlpatterns = [
    path('admin/', admin.site.urls),
    path('health/', health_check, name='health_check'),
    path('auth/', include('authentication.urls')),
    path('api/', include('api.urls')),
] 