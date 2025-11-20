from rest_framework import serializers
from .models import User
from django.contrib.auth.hashers import make_password

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    class Meta:
        model = User
        fields = [
            'user_id',
            'first_name',
            'last_name',
            'email',
            'password',  # input only
            'profile_image',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['user_id', 'created_at', 'updated_at']

    def create(self, validated_data):
        password = validated_data.pop('password')  # remove password from validated_data
        validated_data['password'] = make_password(password)  # hash and assign
        user = User.objects.create(**validated_data)
        return user