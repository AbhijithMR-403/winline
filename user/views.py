import datetime
import json
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view,permission_classes
from django.contrib.auth.hashers import make_password,check_password
from django.core.mail import send_mail
import random
import string
from django.contrib.auth import get_user_model

#from user.signals import create_account_user_mapping
#from .serializer import *
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.contrib.auth import authenticate, login
from .models import *
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from google.oauth2 import id_token
from google.auth.transport import requests
from django.contrib.auth.tokens import PasswordResetTokenGenerator
#from account.serializer import AccountSerializer
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from django.contrib.auth.models import update_last_login
import os, sys
from django.db.models import Q


@api_view(['POST'])
def login_view(request):
    if request.method == 'POST':
        try:
            username = request.data.get('username')
            password = request.data.get('password')
            
            # Check if the user is attempting to login via the admin panel
            if request.path.startswith('/admin/'):
                # Authenticate the user against the default Django user model
                user = authenticate(request, username=email, password=password)
                if user is not None and user.is_superuser:
                    # If superuser authenticated successfully, login and return success response
                    login(request, user)
                    return Response({'message': 'Superuser login successful'})
                else:
                    # If not a superuser or authentication failed, return error response
                    return Response({'error': 'Invalid email or password'}, status=400)
            else:
                # If not attempting to login via admin panel, proceed with custom user authentication
                #custom_user = CustomUser.objects.filter(username=username).first()
                custom_user = CustomUser.objects.filter(Q(email=username) | Q(phoneno=username)).first()
                  
                if custom_user is not None and check_password(password, custom_user.password):
                    # Authenticate user from the CustomUser table
                    #user = authenticate(request, username=username, password=password, backend='user.backends.CustomUserBackend')

                    #token, created = Token.objects.get_or_create(user=user)
                    #update_last_login(None, user)
                    #return Response({'token': token.key}, status=status.HTTP_200_OK)


                    if custom_user is not None:

                        if custom_user.status != "active":
                            return Response({'error': 'Your account is inactive. Please contact the administrator.'}, status=400)
                        
                        #login(request, custom_user)
                        # Generate or fetch existing token for the user
                        token, created = Token.objects.get_or_create(user=custom_user)
                        update_last_login(None, custom_user)
                        # Store token and user ID in session
                        request.session['auth_token'] = token.key
                        request.session['user_id'] = custom_user.id
                        return Response({'message': 'Login successful', 'token': token.key, 'user_role': custom_user.user_role})
                # If authentication fails, return error response
                return Response({'error': 'Invalid email or password'}, status=400)
        except Exception as e:      
            print("Failed to create log file " + e.__str__())            
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

    else:
        # Return error response for non-POST requests
        return Response({'error': 'Only POST requests are allowed'}, status=405)


@csrf_exempt
@api_view(['POST'])
def social_login(request):
    if request.method == 'POST':
        body = json.loads(request.body)
        email = body.get('email')
        token = body.get('token')
        email_type = body.get('domain')

        try:
            if email_type not in ['fb', 'google']:
                raise ValueError('Invalid email type')


            if email_type == 'google':
                idinfo = id_token.verify_oauth2_token(token, requests.Request())
                print(idinfo)
                if idinfo['email'] != email:
                    raise ValueError('Email mismatch in token')
            elif email_type == 'fb':
                
                pass

            user = CustomUser.objects.filter(email=email).first()
            #user = CustomUser.objects.filter(Q(email=username) | Q(phoneno=username)).first()
            
            if user:
                #return Response({'exists': True})    
                token, created = Token.objects.get_or_create(user=user)
                # Store token and user ID in session
                request.session['auth_token'] = token.key
                request.session['user_id'] = user.id
                request.session['user_role'] = user.user_role
                return Response({'message': 'Login successful', 'token': token.key, 'user_role': user.user_role})  
            else:
                return Response({'exists': False})  
        except ValueError as e:
            return Response({'error': str(e)}, status=400)  
    else:
        return Response({'error': 'Only POST requests are allowed'}, status=405) 

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        # Get the token from the request headers
        token_key = request.headers['Authorization'].split(' ')[1]
        # Retrieve the token object
        token = Token.objects.get(key=token_key)
        # Delete the token associated with the user
        token.delete()
        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
    except Token.DoesNotExist:
        return Response({'error': 'Invalid or missing authentication token'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    data = request.data
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_password')

    # Check if new password and confirm new password match
    if new_password != confirm_new_password:
        return Response({'error': 'New password and confirm new password do not match'}, status=status.HTTP_400_BAD_REQUEST)

    # Change the password
    user.set_password(new_password)
    user.save()

    return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)

def user_exists(username):
    return CustomUser.objects.filter(Q(email=username) | Q(phoneno=username)).exists()

@api_view(['POST'])
@permission_classes([])
def forgot_password(request):
    try:
        username = request.data.get('username')
        User = get_user_model()
        userExist =  user_exists(username)
        print("userExist: ",userExist)    
        if userExist:   
            user = User.objects.get(Q(email=username) | Q(phoneno=username))
            token_generator = PasswordResetTokenGenerator()        
            uidb64 = urlsafe_base64_encode(bytes(str(user.pk), 'utf-8'))
            token = token_generator.make_token(user)      
            customUsername = 'nisha.rangan@okirana.com'
            # Construct reset link
            reset_link = request.build_absolute_uri(reverse('reset_password', kwargs={'uidb64': uidb64, 'token': token}))
            send_mail(
                'Password Reset Request',
                f'Click the following link to reset your password: {reset_link}',
                'from@example.com',
                [customUsername],
                fail_silently=False,
            )
            return Response({'message': 'Password reset link sent to your email'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'No user found with this email'}, status=status.HTTP_404_NOT_FOUND)
        
    except Exception as e:                  
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to reset link generate " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def reset_password(request, uidb64, token):
    if request.method == 'POST':
        # Decode user ID from base64
        uid = urlsafe_base64_decode(uidb64).decode('utf-8')
        User = get_user_model()
        try:
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and PasswordResetTokenGenerator().check_token(user, token):
            new_password = request.data.get('new_password')
            confirm_password = request.data.get('confirm_password')
            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)
    return Response({'error': 'Only POST requests are allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
