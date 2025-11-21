import jwt
from functools import wraps
from django.conf import settings
from rest_framework import status
from .models import User, BlacklistedToken
from .functions import api_response


def login_required(view_func):
    """
    Custom decorator to protect API endpoints using JWT tokens.
    """
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):

        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return api_response(False, "Authorization token missing", status.HTTP_401_UNAUTHORIZED)

        token = auth_header.split(" ")[1]

        # Check blacklisted
        if BlacklistedToken.objects.filter(token=token).exists():
            return api_response(False, "Token is invalid or logged out", status.HTTP_401_UNAUTHORIZED)

        try:
            # Decode token
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])

            # Get user
            user = User.objects.filter(user_id=payload.get("user_id")).first()

            if not user:
                return api_response(False, "User does not exist", status.HTTP_401_UNAUTHORIZED)

            # Attach user to request
            request.user = user

        except jwt.ExpiredSignatureError:
            return api_response(False, "Token expired", status.HTTP_401_UNAUTHORIZED)

        except jwt.InvalidTokenError:
            return api_response(False, "Invalid token", status.HTTP_401_UNAUTHORIZED)

        return view_func(self, request, *args, **kwargs)

    return wrapper