from django.urls import path
from .views import SignupView,LoginView,LogoutView,VerifyTokenView


urlpatterns = [
    path("signup/", SignupView.as_view(), name='signup'),
    path("login/", LoginView.as_view(), name='login'),
    path("logout/", LogoutView.as_view(), name='logout'),
    path("verify_token/", VerifyTokenView.as_view(), name='verify_token')

]