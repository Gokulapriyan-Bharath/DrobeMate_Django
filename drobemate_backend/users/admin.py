from django.contrib import admin
from .models import User,BlacklistedToken,PasswordResetOTP

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('first_name', 'last_name', 'email', 'password','profile_image','created_at', 'updated_at')
    search_fields = ('first_name', 'last_name', 'email')

@admin.register(BlacklistedToken)
class BlacklistedTokenAdmin(admin.ModelAdmin):
    list_display = ('token','blacklisted_at')
    search_fields = ('token','blacklisted_at')

@admin.register(PasswordResetOTP)
class PasswordRestOTPAdmin(admin.ModelAdmin):
    list_display = ('user','otp','created_at')
    search_fields = ('user','otp')