from rest_framework.views import APIView
from .serializers import UserSerializer, User,BlacklistedToken
from .functions import api_response, status
from django.contrib.auth.hashers import check_password
from .utils import generate_jwt, decode_jwt, is_token_blacklisted, get_token_from_header, re


class SignupView(APIView):
    """Optimized user signup without profile picture."""
    def post( self, request ):

        data = {
            "first_name": request.data.get("first_name"),
            "last_name": request.data.get("last_name"),
            "email": request.data.get("email"),
            "password": request.data.get("password"),
        }

        # Required field validations
        required_fields = ["first_name", "last_name", "email", "password"]
        for field in required_fields:
            if not data[field]:
                return api_response(
                    success=False,
                    message=f"{field.replace('_', ' ').title()} is required"
                )

        # 3️⃣ Password validation
        password = data["password"]
        if len(password) < 8:
            return api_response(success = False, message = "Password must be at least 8 characters")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return api_response(success = False, message = "Password must contain at least one special character")

        # 5️⃣ Create user
        serializer = UserSerializer(data = data)

        if serializer.is_valid():
            user = serializer.save()
            return api_response(
                success = True,
                message = "User created successfully",
                data = UserSerializer(user).data,
                status_code = status.HTTP_201_CREATED
            )

        # 6️⃣ DRF serializer validation errors
        return api_response(
            success = False,
            message = "Validation failed",
            data = serializer.errors,
            status_code = status.HTTP_400_BAD_REQUEST
        )


class LoginView(APIView):
    def post( self, request ):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = User.objects.get(email = email)
            if not check_password(password, user.password):
                return api_response(False, "Invalid password", None)

            token = generate_jwt(user.pk)

            return api_response(True, "Login successful", data = {"token": token, "expires_in": 86400})

        except User.DoesNotExist:
            return api_response(False, "User not found", None )


class LogoutView(APIView):
    def post(self, request):
        token = get_token_from_header(request)
        if not token:
            return api_response(False, "Token missing", status.HTTP_401_UNAUTHORIZED)
        is_blacklisted = is_token_blacklisted(token)
        if is_blacklisted:
            return api_response(False, "Logged out already", status.HTTP_400_BAD_REQUEST)
        BlacklistedToken.objects.create(token=token)
        return api_response(True, "Logged out successfully")


class VerifyTokenView(APIView):
    def get(self, request):
        token = get_token_from_header(request)

        if not token:
            return api_response(False, "Token missing", status_code=status.HTTP_401_UNAUTHORIZED)

        if is_token_blacklisted(token):
            return api_response(False, "Token blacklisted", status_code=status.HTTP_401_UNAUTHORIZED)

        decoded = decode_jwt(token)

        if decoded == "expired":
            return api_response(False, "Token expired", status_code=status.HTTP_401_UNAUTHORIZED)

        if decoded == "invalid":
            return api_response(False, "Invalid Token", status_code=status.HTTP_401_UNAUTHORIZED)

        user = User.objects.get(pk=decoded["user_id"])
        serializer = UserSerializer(user)

        return api_response(True, "Token valid", data=serializer.data, status_code=status.HTTP_200_OK)
