import uuid
from django.db import models

class User(models.Model):
    user_id = models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    first_name = models.CharField(max_length=100,null=False,blank=False)
    last_name = models.CharField(max_length=100,null=False,blank=False)
    email = models.EmailField(unique=True,null=False,blank=False)
    password = models.TextField(null=True,blank=True)
    profile_image = models.ImageField(upload_to="profile_images/",null=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

class BlacklistedToken(models.Model):
    token = models.TextField()
    blacklisted_at = models.DateTimeField(auto_now_add=True)