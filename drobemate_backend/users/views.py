from rest_framework.views import APIView
from rest_framework import status
from .serializers import UserSerializer, User
from .functions import api_response
import re

class SignupView(APIView):
    """Optimized user signup without profile picture."""

    def post(self, request):

        data = {
            "first_name": request.data.get("first_name"),
            "last_name": request.data.get("last_name"),
            "email": request.data.get("email"),
            "password": request.data.get("password"),
        }

        # 3️⃣ Password validation
        password = data["password"]
        if len(password) < 8:
            return api_response(success=False, message="Password must be at least 8 characters")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return api_response(success=False, message="Password must contain at least one special character")


        # 5️⃣ Create user
        serializer = UserSerializer(data=data)

        if serializer.is_valid():
            user = serializer.save()
            return api_response(
                success=True,
                message="User created successfully",
                data=UserSerializer(user).data,
                status_code=status.HTTP_201_CREATED
            )

        # 6️⃣ DRF serializer validation errors
        return api_response(
            success=False,
            message="Validation failed",
            data=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST
        )