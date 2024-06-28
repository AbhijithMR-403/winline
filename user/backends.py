from django.contrib.auth.backends import ModelBackend, BaseBackend
from django.contrib.auth import get_user_model
from .models import *

class EmailAuthBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        User = get_user_model()
        try:
            user = User.objects.get(email=email)
            print("backends", user)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
        
        
CustomUser = get_user_model()

class CustomUserBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None):
        try:
            # Attempt to retrieve user by email for custom user model
            user = CustomUser.objects.get(email=email)
            if user.check_password(password):
                return user
        except CustomUser.DoesNotExist:
            pass
        return None

    def get_user(self, user_id):
        try:
            return CustomUser.objects.get(pk=user_id)
        except CustomUser.DoesNotExist:
            return None