from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
import re
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site

def api_response(success: bool, message: str, data=None, status_code=status.HTTP_200_OK):
    """
    Standardized API response for both success and error.

    Args:
        success (bool): True for success, False for error.
        message (str): Message describing the response.
        data (any, optional): Additional data to include.
        status_code (int, optional): HTTP status code (default 200).

    Returns:
        rest_framework.response.Response
    """
    return Response({
        "success": success,
        "message": message,
        "data": data
    }, status=status_code)


def validate_password( password ):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"

    return True, "Valid password"
