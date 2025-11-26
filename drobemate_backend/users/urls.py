from django.urls import path
from .views import SignupView,LoginView,LogoutView,VerifyTokenView,UpdateProfileImageView,UpdateUserView,ResetPasswordView,ForgotPasswordOTPView,ResetPasswordUsingOTPView,VerifyOTPView


urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path("logout/", LogoutView.as_view(), name='logout'),
    path('verify_token/', VerifyTokenView.as_view(), name='verify_token'),
    path('update_profile_image/',UpdateProfileImageView.as_view(),name='update_profile_image'),
    path('update_user/', UpdateUserView.as_view(), name = 'update_user'),
    path('reset_password/', ResetPasswordView.as_view(), name = 'reset_password'),
    path('forgot_password/', ForgotPasswordOTPView.as_view(), name='forgot_password'),
    path('verify_otp/', VerifyOTPView.as_view(), name = 'verify_otp'),
    path('reset_password_otp/', ResetPasswordUsingOTPView.as_view(), name = 'reset_password_otp'),

]