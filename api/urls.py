from django.urls import path
from .views import ProfileView, AvatarUploadView

urlpatterns = [
    path('profile/', ProfileView.as_view(), name='profile'),
    path('profile/avatar/', AvatarUploadView.as_view(), name='avatar-upload'),
] 