from rest_framework.views import APIView
from .serializers import UserSerializer, User,BlacklistedToken, make_password, PasswordResetOTP
from .functions import api_response, status, validate_password,send_mail,render_to_string,get_current_site,EmailMessage
from django.contrib.auth.hashers import check_password
from .utils import generate_jwt, decode_jwt, is_token_blacklisted, get_token_from_header
from .decorators import login_required
import random,datetime
from django.utils import timezone


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
                    message=f"{field.replace('_', ' ').title()} is required",status_code = status.HTTP_400_BAD_REQUEST)

        # 3️⃣ Password validation
        password = data["password"]
        valid, msg = validate_password(password)
        if not valid:
            return api_response(False, message = msg,status_code = status.HTTP_400_BAD_REQUEST)

        # 5️⃣ Create user
        serializer = UserSerializer(data = data)

        if serializer.is_valid():
            user = serializer.save()

            return api_response(
                success = True,
                message = "User created successfully",
                data =  {"token": generate_jwt(UserSerializer(user).data["user_id"])},
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
                return api_response(False, "Invalid password", None,status_code = status.HTTP_400_BAD_REQUEST)

            token = generate_jwt(user.pk)

            return api_response(True, "Login successful", data = {"token": token})

        except User.DoesNotExist:
            return api_response(False, "User not found", None,status_code = status.HTTP_400_BAD_REQUEST )

class LogoutView(APIView):
    @login_required
    def post(self, request):
        token = get_token_from_header(request)
        if not token:
            return api_response(False, "Token missing",status_code = status.HTTP_401_UNAUTHORIZED)
        is_blacklisted = is_token_blacklisted(token)
        if is_blacklisted:
            return api_response(False, "Logged out already",status_code = status.HTTP_400_BAD_REQUEST)
        BlacklistedToken.objects.create(token=token)
        return api_response(True, "Logged out successfully")

class VerifyTokenView(APIView):
    @login_required
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

class UpdateProfileImageView(APIView):
    @login_required
    def put(self, request):
        user = request.user   # user is attached by the decorator
        profile_image = request.data.get("profile_image")

        if not profile_image:
            return api_response(False, "Profile image is required",status_code = status.HTTP_400_BAD_REQUEST)

        user.profile_image = profile_image
        user.save()

        return api_response(True, "Profile image updated", UserSerializer(user).data)

class UpdateUserView(APIView):
    """Allows the logged-in user to update their details."""

    @login_required
    def patch(self, request):
        user = request.user   # user is attached by the decorator

        data = {
            "first_name": request.data.get("first_name"),
            "last_name": request.data.get("last_name"),
            "email": request.data.get("email")
        }

        serializer = UserSerializer(user, data=data, partial=True)

        if not serializer.is_valid():
            return api_response(False, serializer.errors, status.HTTP_400_BAD_REQUEST)

        serializer.save()

        return api_response(True, "User Updated successfully", UserSerializer(user).data)

class ResetPasswordView(APIView):
    @login_required
    def patch(self, request):
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        # Validate new password using reusable function
        valid, msg, status_code = validate_password(new_password)
        if not valid:
            return api_response(False, message = msg,status_code = status_code)

        if not old_password or not new_password:
            return api_response(False, "Both fields are required", status_code = status.HTTP_400_BAD_REQUEST)

        user = request.user

        # Check old password
        if not check_password(old_password, user.password):
            return api_response(False, "Old password is incorrect", status_code=status.HTTP_400_BAD_REQUEST)



        # Update password
        user.password = make_password(new_password)
        user.save()

        return api_response(True, "Password updated successfully")

class ForgotPasswordOTPView(APIView):
    def post(self, request ):
        email = request.data.get('email')
        if not email:
            return api_response(False,'Email is Required',data = None,status_code = status.HTTP_400_BAD_REQUEST)

        try :
            user = User.objects.get(email=email)
        except:
            return api_response(False, "User not found",data=None, status_code = status.HTTP_404_NOT_FOUND)

        # ---------- RATE LIMIT: MAX 3 OTP / HOUR ----------
        one_hour_ago = timezone.now() - datetime.timedelta(hours=1)
        otp_count_last_hour = PasswordResetOTP.objects.filter(
            user=user,
            created_at__gte=one_hour_ago
        ).count()

        if otp_count_last_hour >= 3:
            return api_response(
                False,
                "You have reached the maximum OTP requests (3 per hour). Please try again later.",
                None,
                status.HTTP_429_TOO_MANY_REQUESTS
            )
        # -----------------------------------------------------

        otp = str(random.randint(100000, 999999))

        PasswordResetOTP.objects.create(user = user, otp = otp)

        # Build absolute URL for logo (recommended for email clients)
        domain = get_current_site(request).domain
        logo_url = f"https://{domain}/static/images/drobemate_logo.png"

        # Render HTML email template
        html_content = render_to_string("otp_email.html", {
            "username": f"{user.first_name} {user.last_name}",
            "otp": otp,
            "expiry": "5 minutes",
            "logo": logo_url,
        })

        # Send HTML email
        email_message = EmailMessage(
            subject="DrobeMate Password Reset OTP",
            body=html_content,
            from_email="no-reply@drobemate.com",
            to=[email],
        )
        email_message.content_subtype = "html"   # IMPORTANT: tells Django this is HTML
        email_message.send()

        return api_response(True,"OTP sent to your email",None,status_code =status.HTTP_200_OK)

class VerifyOTPView(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        if not email or not otp:
            return api_response(False,"Email and OTP are required",None,status.HTTP_400_BAD_REQUEST)

        try:
            otp_entry = PasswordResetOTP.objects.get(user__email=email, otp=otp)
        except PasswordResetOTP.DoesNotExist:
            return api_response(False,"Invalid email or OTP",None,status.HTTP_400_BAD_REQUEST)

        # Check expiration
        if otp_entry.expired:
            otp_entry.delete()
            return api_response(False,"OTP expired. Please request a new one.",None,status.HTTP_400_BAD_REQUEST)

        return api_response(True,"OTP is valid",None, status.HTTP_200_OK)

class ResetPasswordUsingOTPView(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        new_password = request.data.get("password")

        # 1. Validate fields
        if not email or not otp or not new_password:
            return api_response(
                False,
                "Email, OTP, and new password are required",
                None,
                status.HTTP_400_BAD_REQUEST
            )

        # 2. Validate user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return api_response(False, "User not found", None, status.HTTP_404_NOT_FOUND)

        # 3. Validate OTP entry
        try:
            otp_entry = PasswordResetOTP.objects.get(user=user, otp=otp)
        except PasswordResetOTP.DoesNotExist:
            return api_response(False, "Invalid OTP", None, status.HTTP_400_BAD_REQUEST)

        # 4. Check if OTP expired
        if otp_entry.expired:
            otp_entry.delete()
            return api_response(False, "OTP expired. Request a new one.", None, status.HTTP_400_BAD_REQUEST)

        # 5. Validate password strength
        valid, msg = validate_password(new_password)
        if not valid:
            return api_response(False, msg, None, status_code = status.HTTP_400_BAD_REQUEST)

        user.password = make_password(new_password)
        user.save()

        # 7. Delete OTP after success
        otp_entry.delete()

        return api_response(True, "Password reset successfully", None, status.HTTP_200_OK)
