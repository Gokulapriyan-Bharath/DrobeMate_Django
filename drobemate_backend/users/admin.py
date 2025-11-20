from django.contrib import admin
from .models import User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('first_name', 'last_name', 'email', 'profile_image','created_at', 'updated_at')
    search_fields = ('first_name', 'last_name', 'email')
