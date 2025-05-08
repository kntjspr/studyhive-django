from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Profile

class ProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profiles"""
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    
    class Meta:
        model = Profile
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'avatar', 'bio', 'created_at', 'updated_at']
        read_only_fields = ['id', 'username', 'email', 'first_name', 'last_name', 'created_at', 'updated_at'] 