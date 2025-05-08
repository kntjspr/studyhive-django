from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class RegisterInitSerializer(serializers.Serializer):
    """Serializer for initial registration step"""
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    
    def validate_email(self, value):
        """Validate that email is not already used"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email already exists")
        return value
        
    def validate_password(self, value):
        """Validate password strength"""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

class RegisterCompleteSerializer(serializers.Serializer):
    """Serializer for completing registration (OTP verification)"""
    email = serializers.EmailField(required=True)
    token = serializers.CharField(required=True)
    
class LoginSerializer(serializers.Serializer):
    """Serializer for login with email and password"""
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    
class LoginInitSerializer(serializers.Serializer):
    """Serializer for initiating login"""
    email = serializers.EmailField(required=True)
    
class LoginCompleteSerializer(serializers.Serializer):
    """Serializer for completing login with OTP"""
    email = serializers.EmailField(required=True)
    token = serializers.CharField(required=True)
    
class TokenRefreshSerializer(serializers.Serializer):
    """Serializer for refreshing access token"""
    refresh_token = serializers.CharField(required=True)
    
class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name')
        read_only_fields = ('id', 'username', 'email', 'first_name', 'last_name') 