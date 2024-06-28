from account.models import *
from .models import CustomUser
from user.models import Location
from rest_framework import serializers

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'firstname', 'lastname', 'city', 'state', 'user_role']


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = '__all__'

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField()
    confirm_new_password = serializers.CharField()

class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        #db_table = "location"
        fields = ['id', 'user_id', 'address_line1', 'address_line2', 'cur_town', 'state', 'city', 'district', 'country', 'pincode', 'period_of_stay', 'address_type','default_shipping_flag','default_billing_flag','default_communication']
