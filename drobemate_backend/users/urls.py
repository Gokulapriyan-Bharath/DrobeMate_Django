from django.urls import path
from .views import SignupView,LoginView,LogoutView,VerifyTokenView,UpdateProfileImageView


urlpatterns = [
    path("signup/", SignupView.as_view(), name='signup'),
    path("login/", LoginView.as_view(), name='login'),
    path("logout/", LogoutView.as_view(), name='logout'),
    path("verify_token/", VerifyTokenView.as_view(), name='verify_token'),
    path('update_profile_image/',UpdateProfileImageView.as_view(),name='update_profile_image')
]