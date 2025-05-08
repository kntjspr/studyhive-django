import random
import string
import logging
from datetime import datetime, timedelta
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

# OTP Settings from settings.py
OTP_LENGTH = getattr(settings, 'OTP_LENGTH', 6)
OTP_EXPIRY_MINUTES = getattr(settings, 'OTP_EXPIRY_MINUTES', 10)
OTP_CACHE_PREFIX = "studyhive_otp_"

class ResendAPI:
    """
    Service class for sending emails via the Resend API
    """
    def __init__(self, api_key=None, from_email=None, from_name=None):
        """Initialize Resend API client with credentials"""
        import requests
        self.requests = requests
        self.api_key = api_key or settings.RESEND_API_KEY
        self.from_email = from_email or settings.RESEND_FROM_EMAIL
        self.from_name = from_name or settings.RESEND_FROM_NAME
        self.api_url = "https://api.resend.com/emails"
        
    def send_email(self, to_email, subject, html_content):
        """
        Send an email via Resend API
        
        Args:
            to_email (str or list): Recipient email(s)
            subject (str): Email subject
            html_content (str): HTML email content
            
        Returns:
            dict: API response data or None if request failed
        """
        # Format recipient as list if it's a string
        recipients = to_email if isinstance(to_email, list) else [to_email]
        
        # Prepare request payload
        payload = {
            "from": f"{self.from_name} <{self.from_email}>",
            "to": recipients,
            "subject": subject,
            "html": html_content
        }
        
        # Prepare headers
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Log sanitized request info
        sanitized_headers = headers.copy()
        if 'Authorization' in sanitized_headers:
            sanitized_headers['Authorization'] = 'Bearer [REDACTED]'
            
        logger.info(f"Sending email via Resend: to={recipients}, subject={subject}")
        logger.debug(f"Request headers: {sanitized_headers}")
        
        try:
            # Send request to Resend API
            response = self.requests.post(self.api_url, json=payload, headers=headers)
            
            logger.info(f"Resend API response status: {response.status_code}")
            
            if response.status_code == 200 or response.status_code == 201:
                try:
                    import json
                    result = response.json()
                    logger.info(f"Email sent successfully: {result.get('id')}")
                    return result
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Resend API response: {e}")
                    return None
            else:
                logger.error(f"Resend API error: {response.status_code}")
                logger.error(f"Response content: {response.text}")
                return None
                
        except self.requests.exceptions.RequestException as e:
            logger.error(f"Resend API request failed: {e}")
            return None

def generate_otp(length=OTP_LENGTH):
    """
    Generate a random OTP code of specified length
    
    Args:
        length (int): Length of the OTP code
        
    Returns:
        str: Generated OTP code
    """
    return ''.join(random.choices(string.digits, k=length))

def save_otp(email, otp_code, expiry_minutes=OTP_EXPIRY_MINUTES):
    """
    Save OTP code in cache with expiry time
    
    Args:
        email (str): User's email
        otp_code (str): Generated OTP code
        expiry_minutes (int): Expiry time in minutes
        
    Returns:
        bool: True if OTP was saved successfully
    """
    cache_key = f"{OTP_CACHE_PREFIX}{email}"
    expiry_seconds = expiry_minutes * 60
    
    try:
        # Store OTP in cache with expiry
        cache.set(cache_key, otp_code, expiry_seconds)
        return True
    except Exception as e:
        logger.error(f"Error saving OTP for {email}: {e}")
        return False

def verify_otp(email, otp_code):
    """
    Verify if the provided OTP matches the stored OTP for the email
    
    Args:
        email (str): User's email
        otp_code (str): OTP code to verify
        
    Returns:
        bool: True if OTP is valid, False otherwise
    """
    cache_key = f"{OTP_CACHE_PREFIX}{email}"
    
    # Get stored OTP from cache
    stored_otp = cache.get(cache_key)
    
    # If no OTP found or OTP doesn't match, validation fails
    if not stored_otp or stored_otp != otp_code:
        return False
    
    # Clear OTP after successful verification
    cache.delete(cache_key)
    return True

def send_otp_email(email, otp_code):
    """
    Send OTP verification email to user
    
    Args:
        email (str): User's email
        otp_code (str): OTP code to send
        
    Returns:
        tuple: (success boolean, message string)
    """
    try:
        # Prepare context for email template
        context = {
            'email': email,
            'otp_code': otp_code,
            'expiry_minutes': OTP_EXPIRY_MINUTES
        }
        
        # Render email template
        try:
            html_content = render_to_string('emails/otp_verification.html', context)
        except Exception as e:
            logger.warning(f"Failed to render OTP email template: {e}. Using fallback template.")
            # Simple fallback template
            html_content = f"""
            <html>
            <body>
                <h1>Verify Your Email</h1>
                <p>Hello,</p>
                <p>Your verification code is: <strong>{otp_code}</strong></p>
                <p>This code will expire in {OTP_EXPIRY_MINUTES} minutes.</p>
            </body>
            </html>
            """
        
        plain_content = strip_tags(html_content)
        
        # Create API client
        resend_api = ResendAPI()
        
        # Send email
        response = resend_api.send_email(
            to_email=email,
            subject="Your StudyHive Verification Code",
            html_content=html_content
        )
        
        if response and 'id' in response:
            logger.info(f"OTP email sent to {email}: {response['id']}")
            return True, f"Email delivered with ID: {response['id']}"
        else:
            logger.error(f"Failed to send OTP email to {email}")
            return False, "Email delivery failed"
            
    except Exception as e:
        logger.error(f"Error sending OTP email: {e}")
        return False, str(e) 