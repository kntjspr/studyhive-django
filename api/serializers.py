from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Profile

class ProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profiles"""
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = Profile
        fields = ['id', 'username', 'email', 'bio', 'created_at', 'updated_at']
        read_only_fields = ['id', 'username', 'email', 'created_at', 'updated_at'] 