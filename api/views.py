from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
import cloudinary.uploader
import logging

from .models import Profile
from .serializers import ProfileSerializer
from django.contrib.auth.models import User

logger = logging.getLogger(__name__)

class ProfileView(APIView):
    """
    View for retrieving and updating user profile
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get current user's profile"""
        profile, created = Profile.objects.get_or_create(user=request.user)
        serializer = ProfileSerializer(profile)
        
        return Response({
            'success': True,
            'data': serializer.data
        })
    
    def patch(self, request):
        """Update current user's profile"""
        profile, created = Profile.objects.get_or_create(user=request.user)
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response({
                'success': True,
                'data': serializer.data
            })
        
        return Response({
            'success': False,
            'message': 'Invalid data',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class AvatarUploadView(APIView):
    """
    View for uploading user avatar to Cloudinary
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Upload avatar image to Cloudinary and update profile"""
        if 'avatar' not in request.FILES:
            return Response({
                'success': False,
                'message': 'No image provided'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            # Upload to Cloudinary
            upload_result = cloudinary.uploader.upload(
                request.FILES['avatar'],
                folder="studyhive/avatars",
                use_filename=True,
                unique_filename=True
            )
            
            # Get Cloudinary URL
            avatar_url = upload_result.get('secure_url')
            
            # Update user's profile
            profile, created = Profile.objects.get_or_create(user=request.user)
            profile.avatar = avatar_url
            profile.save()
            
            serializer = ProfileSerializer(profile)
            
            return Response({
                'success': True,
                'message': 'Avatar uploaded successfully',
                'data': serializer.data
            })
            
        except Exception as e:
            logger.error(f"Error uploading avatar: {str(e)}")
            return Response({
                'success': False,
                'message': f'Error uploading avatar: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 