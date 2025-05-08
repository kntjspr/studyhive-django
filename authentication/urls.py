from django.urls import path
from .views import (
    RegisterInitView, RegisterCompleteView,
    LoginView, LoginInitView, LoginCompleteView,
    LogoutView, TokenRefreshView
)

urlpatterns = [
    # Registration endpoints
    path('register/init', RegisterInitView.as_view(), name='register_init'),
    path('register/complete', RegisterCompleteView.as_view(), name='register_complete'),
    
    # Login endpoints
    path('login', LoginView.as_view(), name='login'),
    path('login/init', LoginInitView.as_view(), name='login_init'),
    path('login/complete', LoginCompleteView.as_view(), name='login_complete'),
    
    # Logout endpoint
    path('logout', LogoutView.as_view(), name='logout'),
    
    # Token refresh endpoint
    path('refresh-token', TokenRefreshView.as_view(), name='token_refresh'),
] 