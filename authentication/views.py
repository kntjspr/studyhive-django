import logging
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from django.db import transaction
from django.conf import settings

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    RegisterInitSerializer, RegisterCompleteSerializer,
    LoginSerializer, LoginInitSerializer, LoginCompleteSerializer,
    TokenRefreshSerializer, UserSerializer
)
from .models import PendingRegistration
from .otp import generate_otp, save_otp, verify_otp, send_otp_email

logger = logging.getLogger(__name__)

class RegisterInitView(APIView):
    """
    Initial registration step: Collect email and password and send OTP
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = RegisterInitSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'message': "Validation failed",
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        first_name = serializer.validated_data['first_name']
        last_name = serializer.validated_data['last_name']
        
        # Generate OTP and save it
        otp_code = generate_otp()
        otp_saved = save_otp(email, otp_code)
        
        if not otp_saved:
            return Response({
                'success': False,
                'message': "Failed to generate verification code"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Store registration data temporarily (password hashed)
        try:
            PendingRegistration.objects.update_or_create(
                email=email,
                defaults={
                    'password_hash': make_password(password),
                    'first_name': first_name,
                    'last_name': last_name
                }
            )
        except Exception as e:
            logger.error(f"Error storing pending registration: {e}")
            return Response({
                'success': False,
                'message': "Failed to process registration"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Send OTP via email
        email_sent, message = send_otp_email(email, otp_code)
        
        if not email_sent:
            return Response({
                'success': False,
                'message': f"Failed to send verification code: {message}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        return Response({
            'success': True,
            'message': "Verification code sent to your email",
            'data': {
                'email': email
            }
        }, status=status.HTTP_200_OK)


class RegisterCompleteView(APIView):
    """
    Complete registration by verifying OTP
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = RegisterCompleteSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'message': "Validation failed",
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        email = serializer.validated_data['email']
        token = serializer.validated_data['token']
        
        # Verify OTP
        if not verify_otp(email, token):
            return Response({
                'success': False,
                'message': "Invalid or expired verification code"
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Get pending registration
        try:
            pending_reg = PendingRegistration.objects.get(email=email)
        except PendingRegistration.DoesNotExist:
            return Response({
                'success': False,
                'message': "Registration session expired or not found"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create user account
        try:
            with transaction.atomic():
                # Generate a username based on the email (before @ character)
                username = email.split('@')[0]
                base_username = username
                suffix = 1
                
                # Make sure username is unique
                while User.objects.filter(username=username).exists():
                    username = f"{base_username}{suffix}"
                    suffix += 1
                
                # Create user with stored data
                user = User.objects.create(
                    username=username,
                    email=email,
                    password=pending_reg.password_hash,  # Already hashed
                    first_name=pending_reg.first_name,
                    last_name=pending_reg.last_name
                )
                
                # Clean up pending registration
                pending_reg.delete()
                
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)
                
                return Response({
                    'success': True,
                    'message': "Registration successful",
                    'data': {
                        'user': UserSerializer(user).data,
                        'session': {
                            'access_token': access_token,
                            'refresh_token': refresh_token
                        },
                        'accessToken': access_token
                    }
                }, status=status.HTTP_201_CREATED)
                
        except Exception as e:
            logger.error(f"Error completing registration: {e}")
            return Response({
                'success': False,
                'message': "Failed to complete registration"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginView(APIView):
    """
    Login with email and password
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'message': "Validation failed",
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'message': "No account found with this email"
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Verify password
        if not user.check_password(password):
            return Response({
                'success': False,
                'message': "Invalid credentials"
            }, status=status.HTTP_401_UNAUTHORIZED)
            
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        return Response({
            'success': True,
            'message': "Login successful",
            'data': {
                'user': UserSerializer(user).data,
                'session': {
                    'access_token': access_token,
                    'refresh_token': refresh_token
                },
                'accessToken': access_token
            }
        }, status=status.HTTP_200_OK)


class LoginInitView(APIView):
    """
    Initiate login by sending OTP
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = LoginInitSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'message': "Validation failed",
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        email = serializer.validated_data['email']
        
        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'message': "No account found with this email"
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Generate OTP and save it
        otp_code = generate_otp()
        otp_saved = save_otp(email, otp_code)
        
        if not otp_saved:
            return Response({
                'success': False,
                'message': "Failed to generate verification code"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Send OTP via email
        email_sent, message = send_otp_email(email, otp_code)
        
        if not email_sent:
            return Response({
                'success': False,
                'message': f"Failed to send verification code: {message}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        return Response({
            'success': True,
            'message': "OTP sent to email",
            'data': {
                'user': None,
                'session': None
            }
        }, status=status.HTTP_200_OK)


class LoginCompleteView(APIView):
    """
    Complete login with OTP verification
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = LoginCompleteSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'message': "Validation failed",
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        email = serializer.validated_data['email']
        token = serializer.validated_data['token']
        
        # Verify OTP
        if not verify_otp(email, token):
            return Response({
                'success': False,
                'message': "Invalid or expired verification code"
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Get user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'message': "User not found"
            }, status=status.HTTP_404_NOT_FOUND)
            
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        return Response({
            'success': True,
            'message': "Login successful",
            'data': {
                'user': UserSerializer(user).data,
                'session': {
                    'access_token': access_token,
                    'refresh_token': refresh_token
                },
                'accessToken': access_token
            }
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    Logout user - client-side token removal
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        # No server-side action needed for logout in JWT-based auth
        # Client should simply discard the token
        return Response({
            'success': True,
            'message': "Logged out successfully"
        }, status=status.HTTP_200_OK)


class TokenRefreshView(APIView):
    """
    Refresh access token using refresh token
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = TokenRefreshSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'message': "Validation failed",
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        refresh_token = serializer.validated_data['refresh_token']
        
        try:
            # Verify and create new tokens
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            
            # Optionally get user info
            user_id = refresh.payload.get('user_id')
            user = User.objects.get(id=user_id)
            
            return Response({
                'success': True,
                'data': {
                    'session': {
                        'access_token': access_token,
                        'refresh_token': str(refresh)  # This returns a new refresh token
                    },
                    'user': UserSerializer(user).data
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return Response({
                'success': False,
                'message': "Invalid refresh token"
            }, status=status.HTTP_401_UNAUTHORIZED) 