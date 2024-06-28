from django.shortcuts import render
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
from rest_framework.serializers import ValidationError
from case.models import Case, CaseQuery, CasePurpose, CaseEvaluation, LovSeedData, CaseDisbursement, CaseRepayment
#from .serializer import *
from case.serializers import CaseSerializer, CustomUserSerializer, CaseQuerySerializer, CasePurposeSerializer, CaseEvaluationSerializer, LovSeedDataSerializer, DisbursementSerializer,CustomDisbursementSerializer, RepaymentAdminSerializer, CustomRepaymentAdminSerializer
from user.serializers import LocationSerializer
from user.models import Location
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from .models import *
# from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from google.oauth2 import id_token
from google.auth.transport import requests
from django.contrib.auth.tokens import PasswordResetTokenGenerator
#from account.serializer import AccountSerializer
#from user.serializers import LocationSerializer
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
#from rest_framework import filters
#from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.parsers import MultiPartParser
from rest_framework.decorators import parser_classes
import os, sys
from django.http import HttpRequest
from django.shortcuts import get_object_or_404
import pandas as pd
from datetime import datetime, timedelta
from django.db.models import Q
from django.db.models import Sum
from datetime import date
from decimal import Decimal
from rest_framework import viewsets
from rest_framework.parsers import MultiPartParser, FormParser
from .models import FileUpload
from .serializers import FileUploadSerializer
from account.serializer import AccountSerializer
from account.models import Account
from django.db.models import Count
# Create your views here. 

@permission_classes([IsAuthenticated])
class FileUploadViewSet(viewsets.ModelViewSet):
    queryset = FileUpload.objects.all()
    serializer_class = FileUploadSerializer
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        file_serializer = ImageUploadSerializer(data=request.data)
        if file_serializer.is_valid():
            file_serializer.save()
            return Response(file_serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(file_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def create_co_aplicant_user(data):    
    print("coapplicant")
    #print(data)
    try:
        # Extract email from the request data
        email = data['email']
        print("Co-applicant email: ", email)
        co_app_status = data['status']
        #coapplicant_user_id = 0
       
        userData = {
                    'user_role': 'benefactor',  
                    'is_active': 1,  
                    'default_account_id': 1,             
                    'firstname': data['firstname'] if data['firstname'] else '.', 
                    'lastname': data['lastname'] if data['lastname'] else '.', 
                    'email': data['email'], 
                    'gender': data['gender'],  
                    'dob': data['dob'] if data['dob'] else None, 
                    'phoneno': data['phoneno'], 
                    'nationality': data['nationality'], 
                    'religion': data['religion'], 
                    'marital_status': data['marital_status'], 
                    'highest_education': data['highest_edu'],
                    'profession': data['profession'],
                    #'profile_pic': data['profile_pic'], 
                    'monthly_income': data['monthly_income'] if data['monthly_income'] else '0.00', 
                    'tot_fam_income': data['tot_fam_income'] if data['tot_fam_income'] else '0.00',
                    'tot_dependants': data['tot_dependants'], 
                    'cibil_score': data['cibil_score'], 
                    'covenants_risks': data['covenants_risks'], 
                    'identity_proof': data['identity_proof'],
                    #'identity_proof_copy': data['identity_proof_copy'],
                    'address_proof': data['address_proof'],
                    #'address_proof_copy': data['address_copy'],
                    'income_proof': data['income_proof'],
                    #'income_copy': data['income_copy'], 
                    'status': co_app_status if co_app_status else 'active', 
                    'is_guarantor': 0,
                }    
        print(" ")
        print(userData)
        serializerUser = CustomUserSerializer(data=userData, context={'status': co_app_status}) 
                    
        if serializerUser.is_valid(raise_exception=True):
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            print("Password is: ", password)
            # Save the user                   
            custom_user = serializerUser.save(password=password, status=co_app_status)
            print(custom_user)
            coapplicant_user_id  = custom_user.pk
            print("coapplicant_user_id", coapplicant_user_id)

            if coapplicant_user_id:
                for address in data['address']:                    
                    for addresssub in data['address'][address]:       
                        locationData3 = {
                            'user_id':  coapplicant_user_id, 
                            'address_line1':  data['address'][address]['address_line1'], 
                            'address_line2':  data['address'][address]['address_line2'],  
                            'cur_town': data['address'][address]['cur_town'], 
                            'state': data['address'][address]['state'], 
                            'city': data['address'][address]['city'], 
                            'district': data['address'][address]['district'],  
                            'country': data['address'][address]['country'], 
                            'pincode': data['address'][address]['pincode'], 
                            'period_of_stay': data['address'][address]['period_of_stay'], 
                            'address_type': data['address'][address]['address_type'], 
                            'default_shipping_flag': data['default_shipping_flag'], 
                            'default_billing_flag': data['default_billing_flag'],  
                            'default_communication': data['default_communication'],         
                        }
                        locationData = {
                            'user_id':  coapplicant_user_id, 
                            'address_line1':  data['address'][address]['address_line1'] if data['address'][address]['address_line1'] else None, 
                            'address_line2':  data['address'][address]['address_line2'] if data['address'][address]['address_line2'] else None,  
                            'cur_town': data['address'][address]['cur_town'] if data['address'][address]['cur_town'] else None, 
                            'state': data['address'][address]['state'] if data['address'][address]['state'] else None,
                            'city': data['address'][address]['city'] if data['address'][address]['city'] else None, 
                            'district': data['address'][address]['district'] if data['address'][address]['district'] else None, 
                            'country': data['address'][address]['country'] if data['address'][address]['country'] else None, 
                            'pincode': data['address'][address]['pincode'] if data['address'][address]['pincode'] else None, 
                            'period_of_stay': data['address'][address]['period_of_stay'] if data['address'][address]['period_of_stay'] else None,
                            'address_type': data['address'][address]['address_type'] if data['address'][address]['address_type'] else None, 
                            'default_shipping_flag': data['default_shipping_flag'], 
                            'default_billing_flag': data['default_billing_flag'],  
                            'default_communication': data['default_communication'],         
                        }
                    
                    serializerLoc = LocationSerializer(data=locationData, context={'user_id': coapplicant_user_id})                   
                    if serializerLoc.is_valid(raise_exception=True): 
                        # Save the location                
                        serializerLoc.save()
                        print("valid location for coapplicant data ")
                    else:
                        print("Invalid location for coapplicant data ")  
        else:
            print("Invalid coapplicant data ")  

        return coapplicant_user_id
        
    except Exception as e:
        #error = e.detail
        print("Failed to create log file " + e.__str__())       
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
        return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

def update_co_aplicant_user(data, coapplicant_user_id):
    try:
        user_id = coapplicant_user_id
        co_app_status = data['status']

        # Fetch existing user data
        existing_user = CustomUser.objects.get(pk=user_id)

        # Update User details
        userData = {
            'user_role': 'benefactor',
            'is_active': 1,
            'default_account_id': 1,
            'firstname': data['firstname'] or existing_user.firstname,
            'lastname': data['lastname'] or existing_user.lastname,
            'email': data['email'] or existing_user.email,
            'gender': data['gender'] or existing_user.gender,
            'dob': data['dob'] or existing_user.dob,
            'phoneno': data['phoneno'] or existing_user.phoneno,
            'nationality': data['nationality'] or existing_user.nationality,
            'religion': data['religion'] or existing_user.religion,
            'marital_status': data['marital_status'] or existing_user.marital_status,
            'highest_education': data['highest_edu'] or existing_user.highest_education,
            'profession': data['profession'] or existing_user.profession,
            'monthly_income': data['monthly_income'] or existing_user.monthly_income,
            'tot_fam_income': data['tot_fam_income'] or existing_user.tot_fam_income,
            'tot_dependants': data['tot_dependants'] or existing_user.tot_dependants,
            'cibil_score': data['cibil_score'] or existing_user.cibil_score,
            'covenants_risks': data['covenants_risks'] or existing_user.covenants_risks,
            'identity_proof': data['identity_proof'] or existing_user.identity_proof,
            'address_proof': data['address_proof'] or existing_user.address_proof,
            'income_proof': data['income_proof'] or existing_user.income_proof,
            'status': co_app_status or existing_user.status,
            'is_guarantor': existing_user.is_guarantor,
        }

        coapplicantSerializer = CustomUserSerializer(existing_user, data=userData, partial=True)
        if coapplicantSerializer.is_valid(raise_exception=True):
            coapplicantSerializer.save()
            print("details updated")

        # Update Address details
        for address_type_coap, address_info_coap in data["address"].items():
            existing_location = Location.objects.get(user_id=user_id, address_type=address_info_coap['address_type'])
            locationDataCoApp = {
                'address_line1': address_info_coap['address_line1'] or existing_location.address_line1,
                'address_line2': address_info_coap['address_line2'] or existing_location.address_line2,
                'cur_town': address_info_coap['cur_town'] or existing_location.cur_town,
                'state': address_info_coap['state'] or existing_location.state,
                'city': address_info_coap['city'] or existing_location.city,
                'district': address_info_coap['district'] or existing_location.district,
                'country': address_info_coap['country'] or existing_location.country,
                'pincode': address_info_coap['pincode'] or existing_location.pincode,
                'period_of_stay': address_info_coap['period_of_stay'] or existing_location.period_of_stay,
                'address_type': address_info_coap['address_type'],
            }

            serializerCoApplicantLoc = LocationSerializer(existing_location, data=locationDataCoApp, partial=True)
            if serializerCoApplicantLoc.is_valid():
                serializerCoApplicantLoc.save()
                print("Location CoapplicantUser")

        return user_id
    except Exception as e:
        print("Failed to create log file " + e.__str__())
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
        return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_case(request):
    if request.method == 'POST':
        #print(type(request))

        data = request.data
        user = request.user        
        #benefactor_user_id = user.id    
        #image = request.FILES["b_profile_pic"]     
        # contr +/ and control -/
        
        print(" ")
        try:
            coapplicant_user_id = 0
            existing_coapplicant_user_id       = None
            existing_benefector_user_id        = None
            benefactor_user_id                 = None
            existing_benefector_location_user  = None

            check_existing_coapplicant_user_id = None
            check_existing_coapplicant_email   = None
            check_existing_benefactor_user_id  = None
            check_existing_benefactor_email    = None
            
            # Extract coapplicant from the request data
            coapplicant     = request.data.get("coapplicant")
            approval_status = request.data.get("approval_status")
            
            # Initialize variables to default values
            coapplicant_status = None
            coapplicant_email = None
            coapplicant_phoneno = None

            #existing_coapplicant_user_id
            if coapplicant:              
                coapplicant_status = coapplicant.get('status')
                coapplicant_email = coapplicant.get('email')
                coapplicant_phoneno = coapplicant.get('phoneno')               

                if approval_status != "draft" and approval_status != "new": 
                    if not coapplicant_phoneno:
                        return Response({'Error': 'Co-applicant phone is required'}, status=status.HTTP_400_BAD_REQUEST)

                if coapplicant_email is not None:                     
                    co_applicant_email_exists = CustomUser.objects.filter(email=coapplicant_email).first()
                    if co_applicant_email_exists:
                       #find the existing USER ID for chech user from email and phone
                       check_existing_coapplicant_email = co_applicant_email_exists.id 
                       
                # Check if a user with the same phone exists for coapplicant
                existing_co_app_user = CustomUser.objects.filter(phoneno=coapplicant_phoneno).first()
                if existing_co_app_user:
                    existing_coapplicant_user_id = existing_co_app_user.id

                    #find the existing USER ID for chech user from email and phone
                    check_existing_coapplicant_user_id = existing_co_app_user.id               
                print(" check_existing_coapplicant_user_id: ", check_existing_coapplicant_user_id)                    
                print(" check_existing_coapplicant_email: ", check_existing_coapplicant_email)                    
                 
            # Extract state from the request data
            benefector_status = request.data.get("status")
            userData = {
                    'user_role':  'benefactor',  
                    'is_active': 1,  
                    'default_account_id': 1,             
                    'firstname': data['firstname'], 
                    'lastname': data['lastname'], 
                    'email': data['email'], 
                    'gender': data['gender'],  
                    'dob': data['dob'] if data['dob'] else None,  
                    'phoneno': data['phoneno'], 
                    'nationality': data['nationality'], 
                    'religion': data['religion'], 
                    'marital_status': data['marital_status'], 
                    'highest_education': data['highest_edu'],
                    'profession': data['profession'],
                    'profile_pic': data['profile_pic'], 
                    'monthly_income': data['monthly_income'] if data['monthly_income'] else '0.00', 
                    'tot_fam_income': data['tot_fam_income'] if data['tot_fam_income'] else '0.00',
                    'tot_dependants': data['tot_dependants'], 
                    'cibil_score': data['cibil_score'], 
                    'covenants_risks': data['covenants_risks'], 
                    'identity_proof': data['identity_proof'],
                    'identity_proof_copy': data['identity_proof_copy'],
                    'address_proof': data['address_proof'],
                    'address_proof_copy': data['address_copy'],
                    'income_proof': data['income_proof'],
                    'income_copy': data['income_copy'], 
                    'status': benefector_status if benefector_status else 'active',  
                    'is_guarantor': 0, 
                }

            caseData = {
                    'request_amt':  data['request_amt'],
                    'purpose':  data['purpose'] if data['purpose'] else '',
                    'short_description':  data['short_description'],
                    'has_guarantor':  data['has_guarantor'],
                    'guarantor_user_id':  data['guarantor_user_id'] if data['guarantor_user_id'] else '0',
                    'guarantor_name':  data['guarantor_name'] if data['guarantor_name'] else '', 
                    'guarantor_phone':  data['guarantor_phone'] if data['guarantor_phone'] else '',
                    'guarantor_email':  data['guarantor_email'] if data['guarantor_email'] else '',                      
                    'referred_by':  data['referred_by'],
                    'coordinator_user_id': data['coordinator_user_id'] if data['coordinator_user_id'] else '0', 
                    'grant_type':  data['grant_type'] if data['grant_type'] else '',
                    'approval_status':  data['approval_status'],
                    'disbursement_schedule': data['disbursement_schedule'], 
                    'collateral': data['collateral'], 
                    'case_submit_date': '' if 'case_submit_date' not in data else data['case_submit_date'],
                    'pending_info' : 0,                                 
                    }            
            print(userData)
            print(" ")
            print(caseData)
            print(" ")
            #print(data['coapplicant'])
            print(" ")
            # Extract email from the request data
            email   = request.data.get("email")
            b_phone = request.data.get("phoneno")

            if not b_phone:
               return Response({'Error': 'Benefector phoneno is required'}, status=status.HTTP_400_BAD_REQUEST)
                        
            if email is not None: 
               #existing_user = CustomUser.objects.filter(email=email).first()
               email_exists = CustomUser.objects.filter(email=email).first()
               if email_exists:
                  #find the existing USER ID for chech user from email and phone
                  check_existing_benefactor_email = email_exists.id 
               
            #Check if a user with the same email exists            
            existing_benefector_user = CustomUser.objects.filter(phoneno=b_phone).first()
            if existing_benefector_user:
                existing_benefector_user_id       = existing_benefector_user.id
                #find the existing USER ID for chech user from email and phone
                check_existing_benefactor_user_id = existing_benefector_user.id 

                userData.update({
                    'user_role':  'benefactor',  
                    'is_active': 1,  
                    'default_account_id': 1,             
                    'firstname': data['firstname'] or existing_benefector_user.firstname, 
                    'lastname': data['lastname'] or existing_benefector_user.lastname, 
                    'email': data['email'] or existing_benefector_user.email, 
                    'gender': data['gender'] or existing_benefector_user.gender,  
                    'dob': data['dob'] or existing_benefector_user.dob, 
                    'phoneno': data['phoneno'] or existing_benefector_user.phoneno, 
                    'nationality': data['nationality'] or existing_benefector_user.nationality, 
                    'religion': data['religion'] or existing_benefector_user.religion, 
                    'marital_status': data['marital_status'] or existing_benefector_user.marital_status, 
                    'highest_education': data['highest_edu'] or existing_benefector_user.highest_education,
                    'profession': data['profession'] or existing_benefector_user.profession,
                    #'profile_pic': data['profile_pic'] or existing_benefector_user.profile_pic, 
                    'monthly_income': data['monthly_income'] or existing_benefector_user.monthly_income, 
                    'tot_fam_income': data['tot_fam_income'] or existing_benefector_user.tot_fam_income,
                    'tot_dependants': data['tot_dependants'] or existing_benefector_user.tot_dependants, 
                    'cibil_score': data['cibil_score'] or existing_benefector_user.cibil_score, 
                    'covenants_risks': data['covenants_risks'] or existing_benefector_user.covenants_risks, 
                    'identity_proof': data['identity_proof'] or existing_benefector_user.identity_proof,
                    #'identity_proof_copy': data['identity_proof_copy'] or existing_benefector_user.identity_proof_copy,
                    'address_proof': data['address_proof'] or existing_benefector_user.address_proof,
                    #'address_proof_copy': data['address_copy'] or existing_benefector_user.address_proof_copy,
                    'income_proof': data['income_proof'] or existing_benefector_user.income_proof,
                    #'income_copy': data['income_copy'] or existing_benefector_user.income_copy, 
                    'status': benefector_status or existing_benefector_user.status,  
                    'is_guarantor': 0, 
                })

                existing_benefector_location_user = Location.objects.filter(user_id=existing_benefector_user_id).first()
                         
            # Check if the email is associated with a different user ID
            if check_existing_benefactor_email is not None and check_existing_benefactor_user_id is not None:
                print(f"{check_existing_benefactor_email} is check_existing_benefactor_email and {check_existing_benefactor_user_id} is check_existing_benefactor_user_id")
                if check_existing_benefactor_email != check_existing_benefactor_user_id:
                    return Response({'Error': 'Requested email/phone is already registered with another benefactor'}, status=status.HTTP_400_BAD_REQUEST)
            elif check_existing_benefactor_email is not None and check_existing_benefactor_user_id is None:
                return Response({'Error': 'Requested email/phone is already registered with another benefactor'}, status=status.HTTP_400_BAD_REQUEST)
          
            # case for coapplicant
            if check_existing_coapplicant_email is not None and check_existing_coapplicant_user_id is not None:
                print(f"{check_existing_coapplicant_email} is check_existing_coapplicant_email and {check_existing_coapplicant_user_id} is check_existing_coapplicant_user_id")
                if check_existing_coapplicant_email != check_existing_coapplicant_user_id:
                    return Response({'Error': 'Requested email/phone is already registered with another co-applicant'}, status=status.HTTP_400_BAD_REQUEST)
            elif check_existing_coapplicant_email is not None and check_existing_coapplicant_user_id is None:
                 return Response({'Error': 'Requested email/phone is already registered with another co-applicant'}, status=status.HTTP_400_BAD_REQUEST)
           
            print(" ")
            print("approval_status", approval_status)
            print("existing_coapplicant_user_id", existing_coapplicant_user_id)
            print("coapplicant_phoneno", coapplicant_phoneno)
            print(" ")
            #Call coapplicant method to create user.  
            #print("existing_coapplicant_user_id ffffffff", existing_coapplicant_user_id)              
            if existing_coapplicant_user_id is not None: 
                coapplicant_user_id  = update_co_aplicant_user(data['coapplicant'],existing_coapplicant_user_id)
                print("existing_coapplicant_user_id", existing_coapplicant_user_id)
                caseData['coapplicant_user_id'] = coapplicant_user_id
            else:
                if(approval_status == "draft" or approval_status == "new") and coapplicant_phoneno:   
                   coapplicant_user_id  = create_co_aplicant_user(data['coapplicant'])
                   caseData['coapplicant_user_id'] = coapplicant_user_id
                   print("New coapplicant_user_id", coapplicant_user_id)
                else:
                    print("Conditions not met for creating coapplicant user.")              

            if existing_benefector_user_id is not None:                
                benefactorSerilize = CustomUser.objects.get(pk=existing_benefector_user_id)
                serializerUser     = CustomUserSerializer(benefactorSerilize, data=userData, partial=True)
                print("existing_benefector_user_id", existing_benefector_user_id)  
                if serializerUser.is_valid(raise_exception=True):
                  password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                  print("Update Password is: ", password)
                  # Save the updated benefactor 
                  serializerUser.save(password=password, status=benefector_status)
                  caseData['benefactor_user_id'] = existing_benefector_user_id
                  benefactor_user_id             = existing_benefector_user_id
                  print("benefactor is updated")
                else:                    
                    print("Invalid update benefactor data ") 
            else:
                #Pass state to serializer when creating the serializer instance
                serializerUser = CustomUserSerializer(data=userData, context={'status': benefector_status})
                if serializerUser.is_valid(raise_exception=True):
                   password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                   print("Password added: ", password)
                   # Save the user                   
                   custom_user = serializerUser.save(password=password, status=benefector_status)
                   print(custom_user)
                   benefactor_user_id  = custom_user.pk
                   print("New user_id :", benefactor_user_id)               
                   caseData['benefactor_user_id'] = benefactor_user_id
                else:                    
                    print("Invalid benefactor data ")
            print(" ")

            if benefactor_user_id  is not None: 
                for address_type, address_info in data["address"].items():
                    if not check_existing_benefactor_user_id:
                        locationData = {
                            'user_id': benefactor_user_id,
                            'address_line1': address_info['address_line1'],
                            'address_line2': address_info['address_line2'],
                            'cur_town': address_info['cur_town'],
                            'state': address_info['state'],
                            'city': address_info['city'],
                            'district': address_info['district'],
                            'country': address_info['country'],
                            'pincode': address_info['pincode'],
                            'period_of_stay': address_info['period_of_stay'],
                            'address_type': address_info['address_type'],
                            'default_shipping_flag': data['default_shipping_flag'] if data['default_shipping_flag'] else 0,                        
                            'default_billing_flag':  data['default_billing_flag'] if data['default_billing_flag'] else 0,  
                            'default_communication': data['default_communication'] if data['default_communication'] else 0,                
                      
                        }
                        serializerLocation = LocationSerializer(data=locationData)
                        if serializerLocation.is_valid():
                            serializerLocation.save()
                            print("Location Benefactor Created")

                    if existing_benefector_user_id:
                    #if existing_benefector_location_user is not None and existing_benefector_user_id is not None:
                        existing_location = Location.objects.filter(user_id=existing_benefector_user_id, address_type=address_info['address_type']).first()
                        if existing_location:
                            locationData = {
                                'user_id': existing_benefector_user_id,
                                'address_line1': address_info['address_line1'] or existing_location.address_line1,
                                'address_line2': address_info['address_line2'] or existing_location.address_line2,
                                'cur_town': address_info['cur_town'] or existing_location.cur_town,
                                'state': address_info['state'] or existing_location.state,
                                'city': address_info['city'] or existing_location.city,
                                'district': address_info['district'] or existing_location.district,
                                'country': address_info['country'] or existing_location.country,
                                'pincode': address_info['pincode'] or existing_location.pincode,
                                'period_of_stay': address_info['period_of_stay'] or existing_location.period_of_stay,
                                'address_type': address_info['address_type'],
                                'default_shipping_flag': data['default_shipping_flag'] if data['default_shipping_flag'] else 0,                        
                                'default_billing_flag':  data['default_billing_flag'] if data['default_billing_flag'] else 0,  
                                'default_communication': data['default_communication'] if data['default_communication'] else 0,                
                      
                            }                            
                            serializerLocation = LocationSerializer(existing_location, data=locationData, partial=True)
                            if serializerLocation.is_valid():
                                serializerLocation.save()
                                print("Location Benefactor Updated")
            else:
                print("Invalid user data ")
            
            #print(caseData)
            if benefactor_user_id  is not None:
                serializer = CaseSerializer(data=caseData, context={'benefactor_user_id': benefactor_user_id})
                #print(serializer)
                if serializer.is_valid():
                    # Save the updated account
                    caseId  = serializer.save()
                    case_id = caseId.pk
                    print("case_id :" ,case_id)
                    print("Valid case data")

                    # create the casepurpose data                
                    purpose_queries = request.data.get("purpose_queries")
                    if purpose_queries:

                        #print("purpose_name: ",purpose_queries["purpose_name"])
                        question_details = data["purpose_queries"]["question_details"]

                        # Loop through each question and answer
                        for caseAnswerData in question_details:
                            question = caseAnswerData["question"]
                            answer   = caseAnswerData["answer"]
                            #print(f"Question: {question}")
                            #print(f"Answer: {answer}")
                            #print()  # Print an empty line for better readability                     
                            purposeData = {
                                            'purpose_name': purpose_queries['purpose_name'],
                                            'question_text': question,
                                            'answer_text': answer, 
                                            'case_id': case_id,                                      
                                          }
                            # stored the casepurpose data      
                            purposeData = CasePurpose.objects.create(**purposeData)                        
                            print("Added casepurpose data")
                else:
                    print("Invalid case data ")
                    return Response({'message': 'Invalid case data'}, status=status.HTTP_400_BAD_REQUEST)                  
                return Response({'message': 'Case created successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            #error = e.detail
            print("Failed to create log file " + e.__str__())            
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)


def flatten_dict(d, parent_key='', sep='['):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}]" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            for i, sub_v in enumerate(v):
                items.extend(flatten_dict({i: sub_v}, new_key).items())
        else:
            items.append((new_key, v))
    return dict(items)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_case_31may(request):
    if request.method == 'POST':
        #print(type(request))

        data = request.data
        user = request.user        
        #benefactor_user_id = user.id    
        #image = request.FILES["b_profile_pic"]     
        # contr +/ and control -/
        # Parse the JSON string into a dictionary
        
        flattened_data = flatten_dict(data)
        #print(flattened_data)
        print(" ")
        try:
            coapplicant_user_id = 0
            existing_coapplicant_user_id       = None
            existing_benefector_user_id        = None
            benefactor_user_id                 = None
            existing_benefector_location_user  = None

            check_existing_coapplicant_user_id = None
            check_existing_coapplicant_email   = None
            check_existing_benefactor_user_id  = None
            check_existing_benefactor_email    = None
            
            # Extract coapplicant from the request data
            coapplicant     = data.get("coapplicant")
            approval_status = data.get("approval_status")
            print("vvvvvv ",coapplicant)
            #existing_coapplicant_user_id
            if coapplicant:              
                coapplicant_status  = coapplicant.get('status')
                coapplicant_email   = coapplicant.get('email')
                coapplicant_phoneno = coapplicant.get('phoneno')              
            
                if approval_status != "draft" and approval_status != "new": 
                    if not coapplicant_phoneno:
                        return Response({'Error': 'Co-applicant phone is required'}, status=status.HTTP_400_BAD_REQUEST)

                if coapplicant_email is not None:                     
                    co_applicant_email_exists = CustomUser.objects.filter(email=coapplicant_email).first()
                    if co_applicant_email_exists:
                       #find the existing USER ID for chech user from email and phone
                       check_existing_coapplicant_email = co_applicant_email_exists.id 
                       
                # Check if a user with the same phone exists for coapplicant
                existing_co_app_user = CustomUser.objects.filter(phoneno=coapplicant_phoneno).first()
                if existing_co_app_user:
                    existing_coapplicant_user_id = existing_co_app_user.id

                    #find the existing USER ID for chech user from email and phone
                    check_existing_coapplicant_user_id = existing_co_app_user.id               
                print(" check_existing_coapplicant_user_id: ", check_existing_coapplicant_user_id)                    
                print(" check_existing_coapplicant_email: ", check_existing_coapplicant_email)                    
                 
            # Extract state from the request data
            benefector_status = request.data.get("status")
            userData = {
                    'user_role':  'benefactor',  
                    'is_active': 1,  
                    'default_account_id': 1,             
                    'firstname': data.get('firstname'), 
                    'lastname': data.get('lastname'), 
                    'email': data.get('email'), 
                    'gender': data.get('gender'),  
                    'dob': data.get('dob') if data.get('dob') else None,  
                    'phoneno': data.get('phoneno'), 
                    'nationality': data.get('nationality'), 
                    'religion': data.get('religion'), 
                    'marital_status': data.get('marital_status'), 
                    'highest_education': data.get('highest_edu'),
                    'profession': data.get('profession'),
                    'profile_pic': data.get('profile_pic'), 
                    'monthly_income': data.get('monthly_income') if data.get('monthly_income') else '0.00', 
                    'tot_fam_income': data.get('tot_fam_income') if data.get('tot_fam_income') else '0.00',
                    'tot_dependants': data.get('tot_dependants'), 
                    'cibil_score': data.get('cibil_score'), 
                    'covenants_risks': data.get('covenants_risks'), 
                    'identity_proof': data.get('identity_proof'),
                    'identity_proof_copy': data.get('identity_proof_copy'),
                    'address_proof': data.get('address_proof'),
                    'address_proof_copy': data.get('address_copy'),
                    'income_proof': data.get('income_proof'),
                    'income_copy': data.get('income_copy'), 
                    'status': benefector_status if benefector_status else 'active',  
                    'is_guarantor': 0
                }

            caseData = {
                    'request_amt':  data.get('request_amt'),
                    'purpose':  data.get('purpose') if data.get('purpose') else '',
                    'short_description':  data.get('short_description'),
                    'has_guarantor':  data.get('has_guarantor'),
                    'guarantor_user_id':  data.get('guarantor_user_id') if data.get('guarantor_user_id') else '0',
                    'guarantor_name':  data.get('guarantor_name') if data.get('guarantor_name') else '', 
                    'guarantor_phone':  data.get('guarantor_phone') if data.get('guarantor_phone') else '',
                    'guarantor_email':  data.get('guarantor_email') if data.get('guarantor_email') else '',                      
                    'referred_by':  data.get('referred_by'),
                    'coordinator_user_id': data.get('coordinator_user_id') if data.get('coordinator_user_id') else '0', 
                    'grant_type':  data.get('grant_type') if data.get('grant_type') else '',
                    'approval_status':  data.get('approval_status'),
                    'disbursement_schedule': data.get('disbursement_schedule'), 
                    'collateral': data.get('collateral'), 
                    'case_submit_date': '' if 'case_submit_date' not in data else data.get('case_submit_date'),
                    'pending_info' : 0,                                 
                    }            
            print(userData)
            print(" ")
            print(caseData)
            print(" ")
            #print(coapplicant)
            print(" ")
            # Extract coapplicant data
            coapplicant_data = {k: v for k, v in data.items() if k.startswith('coapplicant')}
            address_data = {k: v for k, v in coapplicant_data.items() if 'address' in k}


            # Extract email from the request data
            email   = data.get("email")
            b_phone = data.get("phoneno")

            if not b_phone:
               return Response({'Error': 'Benefector phoneno is required'}, status=status.HTTP_400_BAD_REQUEST)
                        
            if email is not None: 
               #existing_user = CustomUser.objects.filter(email=email).first()
               email_exists = CustomUser.objects.filter(email=email).first()
               if email_exists:
                  #find the existing USER ID for chech user from email and phone
                  check_existing_benefactor_email = email_exists.id 
               
            #Check if a user with the same email exists            
            existing_benefector_user = CustomUser.objects.filter(phoneno=b_phone).first()
            if existing_benefector_user:
                existing_benefector_user_id       = existing_benefector_user.id
                #find the existing USER ID for chech user from email and phone
                check_existing_benefactor_user_id = existing_benefector_user.id 

                userData.update({
                    'user_role':  'benefactor',  
                    'is_active': 1,  
                    'default_account_id': 1,             
                    'firstname': data.get('firstname') or existing_benefector_user.firstname, 
                    'lastname': data.get('lastname') or existing_benefector_user.lastname, 
                    'email': data.get('email') or existing_benefector_user.email, 
                    'gender': data.get('gender') or existing_benefector_user.gender,  
                    'dob': data.get('dob') or existing_benefector_user.dob, 
                    'phoneno': data.get('phoneno') or existing_benefector_user.phoneno, 
                    'nationality': data.get('nationality') or existing_benefector_user.nationality, 
                    'religion': data.get('religion') or existing_benefector_user.religion, 
                    'marital_status': data.get('marital_status') or existing_benefector_user.marital_status, 
                    'highest_education': data.get('highest_edu') or existing_benefector_user.highest_education,
                    'profession': data.get('profession') or existing_benefector_user.profession,
                    #'profile_pic': data['profile_pic'] or existing_benefector_user.profile_pic, 
                    'monthly_income': data.get('monthly_income') or existing_benefector_user.monthly_income, 
                    'tot_fam_income': data.get('tot_fam_income') or existing_benefector_user.tot_fam_income,
                    'tot_dependants': data.get('tot_dependants') or existing_benefector_user.tot_dependants, 
                    'cibil_score': data.get('cibil_score') or existing_benefector_user.cibil_score, 
                    'covenants_risks': data.get('covenants_risks') or existing_benefector_user.covenants_risks, 
                    'identity_proof': data.get('identity_proof') or existing_benefector_user.identity_proof,
                    #'identity_proof_copy': data['identity_proof_copy'] or existing_benefector_user.identity_proof_copy,
                    'address_proof': data.get('address_proof') or existing_benefector_user.address_proof,
                    #'address_proof_copy': data['address_copy'] or existing_benefector_user.address_proof_copy,
                    'income_proof': data.get('income_proof') or existing_benefector_user.income_proof,
                    #'income_copy': data['income_copy'] or existing_benefector_user.income_copy, 
                    'status': benefector_status or existing_benefector_user.status,  
                    'is_guarantor': 0, 
                })

                existing_benefector_location_user = Location.objects.filter(user_id=existing_benefector_user_id).first()
                         
            # Check if the email is associated with a different user ID
            if check_existing_benefactor_email is not None and check_existing_benefactor_user_id is not None:
                print(f"{check_existing_benefactor_email} is check_existing_benefactor_email and {check_existing_benefactor_user_id} is check_existing_benefactor_user_id")
                if check_existing_benefactor_email != check_existing_benefactor_user_id:
                    return Response({'Error': 'Requested email/phone is already registered with another benefactor'}, status=status.HTTP_400_BAD_REQUEST)
            elif check_existing_benefactor_email is not None and check_existing_benefactor_user_id is None:
                return Response({'Error': 'Requested email/phone is already registered with another benefactor'}, status=status.HTTP_400_BAD_REQUEST)
          
            # case for coapplicant
            if check_existing_coapplicant_email is not None and check_existing_coapplicant_user_id is not None:
                print(f"{check_existing_coapplicant_email} is check_existing_coapplicant_email and {check_existing_coapplicant_user_id} is check_existing_coapplicant_user_id")
                if check_existing_coapplicant_email != check_existing_coapplicant_user_id:
                    return Response({'Error': 'Requested email/phone is already registered with another co-applicant'}, status=status.HTTP_400_BAD_REQUEST)
            elif check_existing_coapplicant_email is not None and check_existing_coapplicant_user_id is None:
                 return Response({'Error': 'Requested email/phone is already registered with another co-applicant'}, status=status.HTTP_400_BAD_REQUEST)
           
            print(" ")
            print("approval_status", approval_status)
            print("existing_coapplicant_user_id", existing_coapplicant_user_id)
            print("coapplicant_phoneno", coapplicant_phoneno)
            print(" ")
            #Call coapplicant method to create user.  
            #print("existing_coapplicant_user_id ffffffff", existing_coapplicant_user_id)              
            if existing_coapplicant_user_id is not None: 
                coapplicant_user_id  = update_co_aplicant_user(data.get("coapplicant"),existing_coapplicant_user_id)
                print("existing_coapplicant_user_id", existing_coapplicant_user_id)
                caseData['coapplicant_user_id'] = coapplicant_user_id
            else:
                if(approval_status == "draft" or approval_status == "new") and coapplicant_phoneno:   
                   coapplicant_user_id  = create_co_aplicant_user(data.get("coapplicant"))
                   caseData['coapplicant_user_id'] = coapplicant_user_id
                   print("New coapplicant_user_id", coapplicant_user_id)
                else:
                    print("Conditions not met for creating coapplicant user.")              

            if existing_benefector_user_id is not None:                
                benefactorSerilize = CustomUser.objects.get(pk=existing_benefector_user_id)
                serializerUser     = CustomUserSerializer(benefactorSerilize, data=userData, partial=True)
                print("existing_benefector_user_id", existing_benefector_user_id)  
                if serializerUser.is_valid(raise_exception=True):
                  password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                  print("Update Password is: ", password)
                  # Save the updated benefactor 
                  serializerUser.save(password=password, status=benefector_status)
                  caseData['benefactor_user_id'] = existing_benefector_user_id
                  benefactor_user_id             = existing_benefector_user_id
                  print("benefactor is updated")
                else:                    
                    print("Invalid update benefactor data ") 
            else:
                #Pass state to serializer when creating the serializer instance
                serializerUser = CustomUserSerializer(data=userData, context={'status': benefector_status})
                if serializerUser.is_valid(raise_exception=True):
                   password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                   print("Password added: ", password)
                   # Save the user                   
                   custom_user = serializerUser.save(password=password, status=benefector_status)
                   print(custom_user)
                   benefactor_user_id  = custom_user.pk
                   print("New user_id :", benefactor_user_id)               
                   caseData['benefactor_user_id'] = benefactor_user_id
                else:                    
                    print("Invalid benefactor data ")
            print(" ")

            if benefactor_user_id  is not None: 
                for address_type, address_info in data.get("address").items():
                    if not check_existing_benefactor_user_id:
                        locationData = {
                            'user_id': benefactor_user_id,
                            'address_line1': address_info['address_line1'],
                            'address_line2': address_info['address_line2'],
                            'cur_town': address_info['cur_town'],
                            'state': address_info['state'],
                            'city': address_info['city'],
                            'district': address_info['district'],
                            'country': address_info['country'],
                            'pincode': address_info['pincode'],
                            'period_of_stay': address_info['period_of_stay'],
                            'address_type': address_info['address_type'],
                            'default_shipping_flag': data['default_shipping_flag'] if data['default_shipping_flag'] else 0,                        
                            'default_billing_flag':  data['default_billing_flag'] if data['default_billing_flag'] else 0,  
                            'default_communication': data['default_communication'] if data['default_communication'] else 0,                
                      
                        }
                        serializerLocation = LocationSerializer(data=locationData)
                        if serializerLocation.is_valid():
                            serializerLocation.save()
                            print("Location Benefactor Created")

                    if existing_benefector_user_id:
                    #if existing_benefector_location_user is not None and existing_benefector_user_id is not None:
                        existing_location = Location.objects.filter(user_id=existing_benefector_user_id, address_type=address_info['address_type']).first()
                        if existing_location:
                            locationData = {
                                'user_id': existing_benefector_user_id,
                                'address_line1': address_info['address_line1'] or existing_location.address_line1,
                                'address_line2': address_info['address_line2'] or existing_location.address_line2,
                                'cur_town': address_info['cur_town'] or existing_location.cur_town,
                                'state': address_info['state'] or existing_location.state,
                                'city': address_info['city'] or existing_location.city,
                                'district': address_info['district'] or existing_location.district,
                                'country': address_info['country'] or existing_location.country,
                                'pincode': address_info['pincode'] or existing_location.pincode,
                                'period_of_stay': address_info['period_of_stay'] or existing_location.period_of_stay,
                                'address_type': address_info['address_type'],
                                'default_shipping_flag': data['default_shipping_flag'] if data['default_shipping_flag'] else 0,                        
                                'default_billing_flag':  data['default_billing_flag'] if data['default_billing_flag'] else 0,  
                                'default_communication': data['default_communication'] if data['default_communication'] else 0,                
                      
                            }                            
                            serializerLocation = LocationSerializer(existing_location, data=locationData, partial=True)
                            if serializerLocation.is_valid():
                                serializerLocation.save()
                                print("Location Benefactor Updated")
            else:
                print("Invalid user data ")
            
            #print(caseData)
            if benefactor_user_id  is not None:
                serializer = CaseSerializer(data=caseData, context={'benefactor_user_id': benefactor_user_id})
                #print(serializer)
                if serializer.is_valid():
                    # Save the updated account
                    caseId  = serializer.save()
                    case_id = caseId.pk
                    print("case_id :" ,case_id)
                    print("Valid case data")

                    # create the casepurpose data                
                    purpose_queries = request.data.get("purpose_queries")
                    if purpose_queries:

                        #print("purpose_name: ",purpose_queries["purpose_name"])
                        question_details = data.get["purpose_queries"]["question_details"]

                        # Loop through each question and answer
                        for caseAnswerData in question_details:
                            question = caseAnswerData["question"]
                            answer   = caseAnswerData["answer"]
                            #print(f"Question: {question}")
                            #print(f"Answer: {answer}")
                            #print()  # Print an empty line for better readability                     
                            purposeData = {
                                            'purpose_name': purpose_queries['purpose_name'],
                                            'question_text': question,
                                            'answer_text': answer, 
                                            'case_id': case_id,                                      
                                          }
                            # stored the casepurpose data      
                            purposeData = CasePurpose.objects.create(**purposeData)                        
                            print("Added casepurpose data")
                else:
                    print("Invalid case data ")
                    return Response({'message': 'Invalid case data'}, status=status.HTTP_400_BAD_REQUEST)                  
                return Response({'message': 'Case created successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            #error = e.detail
            print("Failed to create log file " + e.__str__())            
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_case_list(request):
    try:
        if request.method == 'POST':
            #print("ddd", type(request.data))
            data = request.data
            user = request.user
            print("USER: ",user.id)       
            benefactor_user_id = user.id
           
            user_mappings = CustomUser.objects.filter(email=user).first()

            # Check if there are no account mappings for the user
            if not user_mappings:
                return Response({'Error': 'Wrong benefactor details'}, status=status.HTTP_404_NOT_FOUND)
            
            userserializer = CustomUserSerializer(user_mappings, many=False)
            userData = userserializer.data        
             
            if not request.data:
               my_values = ['new','verification','evaluation','approved','disbursement','repayment']
            else:
                if data['status'] == 'draft':
                    my_values = ['draft']
                elif data['status'] == 'rejected':
                    my_values = ['rejected']
                elif data['status'] == 'closed':
                    my_values = ['closed']
                else:
                    my_values = ['new','verification','evaluation','approved','disbursement','repayment']   

            #cases      = Case.objects.filter(benefactor_user_id=benefactor_user_id) 
            #cases      = Case.objects.all().order_by('-id').values()  
            cases      = Case.objects.filter(approval_status__in=my_values).order_by('-id').values()  
        

            serializer = CaseSerializer(cases, many=True)
            Data   = serializer.data
              
                
            #return Response(serializerLoc.data, status=status.HTTP_200_OK)
            list = []       
            for caseData in Data:
               
                #print("benefactor_user_id",caseData['benefactor_user_id'])
                users = CustomUser.objects.filter(pk=caseData['benefactor_user_id'])
                userserialize = CustomUserSerializer(users, many=True)            
                #userData2 = userserialize.data

                locations = Location.objects.filter(user_id=caseData['benefactor_user_id'])
                serializerLoc = LocationSerializer(data=locations, many=True)
                serializerLoc.is_valid()

                #listLoc = []  
                #locationData = []
                address_dict = {}
                for locData in serializerLoc.data:        

                    addressType = 'current_address' if locData['address_type'] == 'temporary' else 'permanent_address'
                   
                    address_dict[addressType] =  {
                                        'id': locData['id'], 
                                        'user_id': locData['user_id'], 
                                        'address_line1': locData['address_line1'], 
                                        'address_line2': locData['address_line2'],          
                                        'cur_town':locData['cur_town'], 
                                        'state': locData['state'], 
                                        'city': locData['city'], 
                                        'district': locData['district'],  
                                        'country': locData['country'], 
                                        'pincode': locData['pincode'], 
                                        'period_of_stay': locData['period_of_stay'], 
                                        'address_type': locData['address_type'], 
                                        #'default_shipping_flag': locData['default_shipping_flag'], 
                                        #'default_billing_flag': locData['default_billing_flag'],  
                                        #'default_communication': locData['default_communication'], 
                                        }                             

                    #listLoc.append(locationData)
                
                for userData2 in userserialize.data:
                    #print(userData2)
                    pending_info  = CaseQuery.objects.filter(case_id=caseData['id'], answer_text__isnull=True).exists()
                    caseDataFinal =  {
                                    "user_id":caseData['benefactor_user_id'],
                                    "case_id":caseData['id'],
                                    "purpose":caseData['purpose'],
                                    "short_description":caseData['short_description'],
                                    "firstname":userData2['firstname'],
                                    "lastname":userData2['lastname'],
                                    "gender":userData2['gender'],
                                    "dob":userData2['dob'],
                                    "phoneno":userData2['phoneno'],
                                    "email":userData2['email'],
                                    "profile_pic":userData2['profile_pic'],                                
                                    "profession":userData2['profession'],                            
                                    "monthly_income":userData2['monthly_income'],                               
                                    "status":userData2['status'],                            
                                    "request_amt":caseData['request_amt'],                               
                                    'coapplicant_user_id': caseData['coapplicant_user_id'], 
                                    "guarantor_name":caseData['guarantor_name'],                                
                                    "guarantor_email":caseData['guarantor_email'],
                                    "referred_by":caseData['referred_by'],                            
                                    "approval_status":caseData['approval_status'],
                                    "disbursement_schedule": caseData['disbursement_schedule'],
                                    "grant_type":caseData['grant_type'],
                                    "collateral":caseData['collateral'],
                                    #"case_submit_date":caseData['case_submit_date'],
                                    "pending_info":pending_info, 
                                    "repay_disburs":getDisbursRepayDays(caseData['id']),                               
                                    "address":address_dict
                                }
                    
                    # Re arrange the data and added the customer columns in the case info
                    caseDataFinal = reArrange_json(caseDataFinal)

                    list.append(caseDataFinal)
               
            #return Response(serializer.data)
            return Response(list, status=status.HTTP_200_OK)
    except Exception as e:      
        print("Failed to create log file " + e.__str__())            
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
        return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

  
def get_last_child_SeedData(lov_parent_code):
    try: 
        #print("lov_parent_code: ",lov_parent_code)        

        childPurpose       = LovSeedData.objects.filter(lov_parent_code=lov_parent_code)         
        serializerchildPurpose = LovSeedDataSerializer(childPurpose, many=True)       
        #childPurposeData   = serializerchildPurpose.data 
        #serializerchildPurpose.is_valid() 

        childPurpose = [] 
        for childPurposeData in serializerchildPurpose.data:

               childPurposeData = {
                                    #childPurposeData['lov_code'] : childPurposeData['display_label'],
                                    "label": childPurposeData['display_label'] ,"value": childPurposeData['lov_code'],
                                   }
               childPurpose.append(childPurposeData)     
        return childPurpose
    except Exception as e:        
        exc_type, exc_obj, exc_tb = sys.exc_info()                  
        print("failed with: " + __file__ + " at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())


def get_first_child_SeedData_not_need(purEdu):
    try: 
        print("purEdu: ",purEdu)       

        parentPurpose           = LovSeedData.objects.filter(lov_parent_code=purEdu)        
        serializerparentPurpose = LovSeedDataSerializer(parentPurpose, many=True)
        #print(serializerparentPurpose.data)
       
        parentPurpose = []  
        for parentPurposeData in serializerparentPurpose.data:                         
               #print(parentPurposeData)
               #print(parentPurposeData['display_label'] if parentPurposeData['display_label'] else 'NULL')
               #print(parentPurposeData['input_type'] if parentPurposeData['input_type'] else 'NULL')
               #print(parentPurposeData['lov_code'] if parentPurposeData['lov_code'] else 'NULL')
               #print(parentPurposeData['lov_ref_code'] if parentPurposeData['lov_ref_code'] else 'NULL')
               #print("--------")

               parentPurposeData = {
                                    'label': parentPurposeData['display_label'] if parentPurposeData['display_label'] else 'NULL', 
                                    'type': parentPurposeData['input_type'] if parentPurposeData['input_type'] else 'NULL', 
                                    'name': parentPurposeData['lov_code'] if parentPurposeData['lov_code'] else 'NULL',  
                                    'children':  get_last_child_SeedData(parentPurposeData['lov_ref_code']) if parentPurposeData['lov_ref_code'] else []

                                    }   
               parentPurpose.append(parentPurposeData)        
        return parentPurpose
    except Exception as e:        
        exc_type, exc_obj, exc_tb = sys.exc_info()                  
        print("failed with: " + __file__ + " at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_purpose_details(request):
    if request.method == 'GET':
        
        data = request.data
        #print(data)
        # Extract case_id from the request data
        display_label = request.query_params.get("display_label")
       
        #print(display_label)       
        

        #get the case evaluation data
        purpose      = LovSeedData.objects.filter(lov_parent_code="purpose", display_label=display_label)
        serializerPurpose = LovSeedDataSerializer(purpose, many=True)
        purposeData   = serializerPurpose.data

        if purposeData: 
            print(purposeData[0]['lov_code'])
            purEdu   = purposeData[0]['lov_code']

            parentPurpose           = LovSeedData.objects.filter(lov_parent_code=purEdu)        
            serializerparentPurpose = LovSeedDataSerializer(parentPurpose, many=True)
            #print(serializerparentPurpose.data)
           
            parentPurpose = []  
            for parentPurposeData in serializerparentPurpose.data:                         
                   #print(parentPurposeData)
                   #print(parentPurposeData['display_label'] if parentPurposeData['display_label'] else 'NULL')
                   #print(parentPurposeData['input_type'] if parentPurposeData['input_type'] else 'NULL')
                   #print(parentPurposeData['lov_code'] if parentPurposeData['lov_code'] else 'NULL')
                   #print(parentPurposeData['lov_ref_code'] if parentPurposeData['lov_ref_code'] else 'NULL')
                   #print("--------")

                   parentPurposeData = {
                                        'label': parentPurposeData['display_label'] if parentPurposeData['display_label'] else 'NULL', 
                                        'type': parentPurposeData['input_type'] if parentPurposeData['input_type'] else 'NULL', 
                                        'name': parentPurposeData['lov_code'] if parentPurposeData['lov_code'] else 'NULL',  
                                        'children':  get_last_child_SeedData(parentPurposeData['lov_ref_code']) if parentPurposeData['lov_ref_code'] else []

                                        }   
                   parentPurpose.append(parentPurposeData)
            return Response(parentPurpose, status=status.HTTP_200_OK)
        else:
            #return Response("Error: wrong data", status=status.HTTP_400_BAD_REQUEST)
            return Response({'error': 'Invalid or wrong purpose data'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_search_user(request):
    if request.method == 'GET':
        
        queryset = CustomUser.objects.all()
        search_params = request.query_params
        region_separator = " "
        if 'query' in search_params:
            query = search_params['query']
            for searchData in query.split(region_separator):
                queryset = queryset.filter(
                    Q(email__icontains=searchData) |
                    Q(phoneno__icontains=searchData) |
                    Q(firstname__icontains=searchData) |
                    Q(lastname__icontains=searchData)
                )

                serializer = CustomUserSerializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_search_case(request):
    if request.method == 'GET':
        
        queryset = Case.objects.all()
        search_params = request.query_params
        region_separator = " "
        if 'query' in search_params:
            query = search_params['query']
            for searchData in query.split(region_separator):
                queryset = queryset.filter(
                    Q(short_description__icontains=searchData) |
                    Q(guarantor_name__icontains=searchData) |
                    Q(guarantor_phone__icontains=searchData) |
                    Q(guarantor_email__icontains=searchData) |
                    Q(disbursement_schedule__icontains=searchData) |
                    Q(grant_type__icontains=searchData) |
                    Q(collateral__icontains=searchData) 
                )

                serializer = CaseSerializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_case_details(request):
    if request.method == 'GET':
        try: 
            data = request.data
            user = request.user
            print("USER_ID: ",user.id)
            benefactor_user_id = user.id    
            # Extract case_id from the request data
            request_case_id = request.query_params.get("case_id")            

            CaseModel = Case.objects.filter(pk=request_case_id).first()
            serializerCase = CaseSerializer(CaseModel)
            caseData   = serializerCase.data 

            pending_questions  = CaseQuery.objects.filter(case_id=request_case_id, answer_text__isnull=True).exists()
            # Set pending_info to True if there are any null answers, otherwise False
            pending_info = pending_questions            
            # Update the Case model
            Case.objects.filter(pk=request_case_id).update(pending_info=pending_info)

            #Added the customer columns in the case info
            repay_disburs = getDisbursRepayDays(request_case_id)
            caseData.update(repay_disburs)
            #End code here

            case_benefactor_user_id = caseData.get('benefactor_user_id')
            print("Case benefactor_user_id", caseData.get('benefactor_user_id'))
            #if CaseQuery_exists:

            #validUserCheck = CustomUser.objects.filter(email=user).first()
            validUserCheck = CustomUser.objects.filter(pk=case_benefactor_user_id).first()

            # Check if there are no account mappings for the user
            if not validUserCheck:
                return Response({'Error': 'Wrong benefactor details'}, status=status.HTTP_404_NOT_FOUND)
            
            locations = Location.objects.filter(user_id=case_benefactor_user_id)
            serializerLoc = LocationSerializer(data=locations, many=True)
            serializerLoc.is_valid()

           
            #listLoc      = [] 
            # Initialize a dictionary to store addresses
            address_dict_old = {
                'current_address': {},
                'permanent_address': {}
            }
            address_dict = {}
            for locData in serializerLoc.data:        
                addressType = 'current_address' if locData['address_type'] == 'temporary' else 'permanent_address'
                print(addressType)
                address_dict[addressType] =  {
                                    'id': locData['id'], 
                                    'user_id': locData['user_id'], 
                                    'address_line1': locData['address_line1'], 
                                    'address_line2': locData['address_line2'],          
                                    'cur_town':locData['cur_town'], 
                                    'state': locData['state'], 
                                    'city': locData['city'], 
                                    'district': locData['district'],  
                                    'country': locData['country'], 
                                    'pincode': locData['pincode'], 
                                    'period_of_stay': locData['period_of_stay'], 
                                    'address_type': locData['address_type'],
                                    'default_shipping_flag': locData['default_shipping_flag'], 
                                    'default_billing_flag': locData['default_billing_flag'],  
                                    'default_communication': locData['default_communication'],                                
                                    }

            #listLoc.append(address_dict)
            #print(address_dict)
            userserializer = CustomUserSerializer(validUserCheck, many=False)
            userData = userserializer.data   
            #print(userData)
            pending_info  = CaseQuery.objects.filter(case_id=request_case_id, answer_text__isnull=True).exists()
            benefactorData = {            
                                "user_id":userData['id'],                     
                                "firstname":userData['firstname'],
                                "lastname":userData['lastname'],
                                "gender":userData['gender'],
                                "dob":userData['dob'],
                                "phoneno":userData['phoneno'],
                                "email":userData['email'],
                                "profile_pic":userData['profile_pic'],
                                "nationality":userData['nationality'],
                                "religion":userData['religion'],
                                "marital_status":userData['marital_status'],
                                "highest_edu":userData['highest_education'],
                                "profession":userData['profession'],                            
                                "monthly_income":userData['monthly_income'],
                                "tot_fam_income":userData['tot_fam_income'],
                                "tot_dependants":userData['tot_dependants'],
                                "cibil_score":userData['cibil_score'],
                                "covenants_risks":userData['covenants_risks'],
                                "identity_proof":userData['identity_proof'],
                                "identity_proof_copy":userData['identity_proof_copy'],
                                "address_proof":userData['address_proof'],
                                "address_copy":userData['address_proof_copy'],
                                "income_proof":userData['income_proof'],
                                "income_copy":userData['income_copy'],
                                "is_guarantor":userData['is_guarantor'],
                                "status":userData['status'], 
                                "address" : address_dict,              
                            }            

            #listLoc.append(locationData)           
            #coapplicant_user_id = request.query_params.get("coapplicant_user_id")
            # get the coapplicant_user_id by case_id from db
            coapplicant_user_id = caseData.get('coapplicant_user_id')
            # #get the case query data
            caseQry      = CaseQuery.objects.filter(case_id=request_case_id)        
            serializerCaseQuery = CaseQuerySerializer(caseQry, many=True)
            DataCaseQry   = serializerCaseQuery.data
            
            #get the case purpose data
            casePur           = CasePurpose.objects.filter(case_id=request_case_id)        
            serializerCasePur = CasePurposeSerializer(casePur, many=True)
            DatacasePur   = serializerCasePur.data
            
            #get the case evaluation data
            casesEval      = CaseEvaluation.objects.filter(case_id=request_case_id)        
            serializerCaseEval = CaseEvaluationSerializer(casesEval, many=True)
            DataEval   = serializerCaseEval.data
            
            #print("benefactor_user_id: ",user.id)
            # Get the case details
            #cases      = Case.objects.filter(id=request_case_id)        
            #serializer = CaseSerializer(cases, many=True)
            #Data   = serializer.data            

            #list = []       
            #for caseData in Data:
            #    print(caseData)          
               
                            
                #list.append(caseDataFinal)
            casePurposeData =  {
                                "purpose_name": caseData.get('purpose'),
                                "question_details": DatacasePur
                                }
            caseDataFinal = {
                                "benefactor":benefactorData,
                                "co_applicant_details": get_co_applicant_details(coapplicant_user_id) or [],
                                "case_info":caseData,
                                "case_query":DataCaseQry,
                                "purpose_queries":casePurposeData,
                                "case_evaluation":DataEval,
                            }
            #return Response(serializer.data)
            return Response(caseDataFinal, status=status.HTTP_200_OK)
        except Exception as e:
            #error = e.detail
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("Failed to create log file " + e.__str__())
            print(" ")            
            print("failed with: " + __file__ + " at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            print(" ")
            return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

def get_co_applicant_details(coAppUserId):
    try: 
        print("coAppUserId: ",coAppUserId)
        co_applicant_user_id = coAppUserId
        benefactorData = []  
        
        # Check if a CustomUser object with the specified pk exists
        #validCoApplicant = CustomUser.objects.filter(pk=co_applicant_user_id).exist()
        validCoApplicant = CustomUser.objects.filter(pk=co_applicant_user_id).first()
        #print("validCoApplicant: ",validCoApplicant)

        # Alternatively, if you want to retrieve the object if it exists:
        #validCoApplicant = get_object_or_404(CustomUser, pk=co_applicant_user_id)
          
        locations = Location.objects.filter(user_id=co_applicant_user_id)
        serializerLoc = LocationSerializer(data=locations, many=True)
        serializerLoc.is_valid()
        listLoc = []
        coapplicant_add_dict = {}
        for locData in serializerLoc.data:        
            addressType = 'current_address' if locData['address_type'] == 'temporary' else 'permanent_address'
            coapplicant_add_dict[addressType] =  {
                                'id': locData['id'], 
                                'user_id': locData['user_id'], 
                                'address_line1': locData['address_line1'], 
                                'address_line2': locData['address_line2'],          
                                'cur_town':locData['cur_town'], 
                                'state': locData['state'], 
                                'city': locData['city'], 
                                'district': locData['district'],  
                                'country': locData['country'], 
                                'pincode': locData['pincode'], 
                                'period_of_stay': locData['period_of_stay'], 
                                'address_type': locData['address_type'],
                                'default_shipping_flag': locData['default_shipping_flag'], 
                                'default_billing_flag': locData['default_billing_flag'],  
                                'default_communication': locData['default_communication'],                                
                                }                
                           
            #listLoc.append(locationData)
            #print(locationData)
        benefactorData = []
        userserializer = CustomUserSerializer(validCoApplicant, many=False)
        userData = userserializer.data   
        #print(locationData)
        benefactorData = {            
                            "user_id":userData['id'],                     
                            "firstname":userData['firstname'],
                            "lastname":userData['firstname'],
                            "gender":userData['gender'],
                            "dob":userData['dob'],
                            "phoneno":userData['phoneno'],
                            "email":userData['email'],
                            "profile_pic":userData['profile_pic'],
                            "nationality":userData['nationality'],
                            "religion":userData['religion'],
                            "marital_status":userData['marital_status'],
                            "highest_edu":userData['highest_education'],
                            "profession":userData['profession'],                            
                            "monthly_income":userData['monthly_income'],
                            "tot_fam_income":userData['tot_fam_income'],
                            "tot_dependants":userData['tot_dependants'],
                            "cibil_score":userData['cibil_score'],
                            "covenants_risks":userData['covenants_risks'],
                            "identity_proof":userData['identity_proof'],
                            "identity_proof_copy":userData['identity_proof_copy'],
                            "address_proof":userData['address_proof'],
                            "address_copy":userData['address_proof_copy'],
                            "income_proof":userData['income_proof'],
                            "income_copy":userData['income_copy'],
                            "is_guarantor":userData['is_guarantor'],
                            "status":userData['status'], 
                            "address" : coapplicant_add_dict,              
                        }      
       
        return benefactorData
    except Exception as e:        
        exc_type, exc_obj, exc_tb = sys.exc_info()                  
        print("failed with: " + __file__ + " at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
       

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_case_details(request, case_id):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            data    = request.data
            print(data)
            user    = request.user
            user_id = user.id    
            print("case_id: ",case_id)    
            benefactor_user_id = data['benefactor']['user_id']
            print("user_id: ",benefactor_user_id)          
            # initialize prefix
            pref = 'b_'             
            # Remove prefix strings from list
            # using loop + remove() + startswith()
            benefactor = []
           
            for key, value in data['benefactor'].items():              
                keyData = key.replace(pref, '')
                benefactorData = {keyData: value,}
                benefactor.append(benefactorData)
            #print(benefactor)
            finalBenefactorData = {}
            for item in benefactor:
                finalBenefactorData.update(item)
            #print (finalBenefactorData)

            customUser = CustomUser.objects.get(pk=benefactor_user_id) 
            #print(" ",finalBenefactorData)           
            # Serialize the request data
            serializerUser = CustomUserSerializer(customUser, data=finalBenefactorData, partial=True)
            #print(serializerUser) 
            if serializerUser.is_valid(raise_exception=True):
                # Save the updated benefactor
                serializerUser.save()            

                for address_type, address_info in data["benefactor"]["address"].items():
                    #print(address_type)
                    #print(address_info)
                    #print("City:", address_info["city"])
                    #print("Address line 1:", address_info["address_line1"])
                    print()  # for spacing between addresses
                    #print("AddressID: ",address_info['id'])
                    #if address_info['id'] == None:
                    if isinstance(address_info, dict) and address_info.get('id') is None:                          
                        locationAddData = {                        
                            'user_id':  benefactor_user_id, 
                            'address_line1':  address_info['address_line1'], 
                            'address_line2':  address_info['address_line2'],  
                            'cur_town': address_info['cur_town'], 
                            'state': address_info['state'], 
                            'city': address_info['city'], 
                            'district': address_info['district'],  
                            'country': address_info['country'], 
                            'pincode': address_info['pincode'], 
                            'period_of_stay': address_info['period_of_stay'], 
                            'address_type': address_info['address_type']                   
                        }
                        # add the new row if new address not exist in location table                       
                        benefctAddLoc = Location.objects.create(**locationAddData)                        
                    else:
                        locationData = {
                            'user_id':  benefactor_user_id,                         
                            'address_line1':  address_info['address_line1'], 
                            'address_line2':  address_info['address_line2'],  
                            'cur_town': address_info['cur_town'], 
                            'state': address_info['state'], 
                            'city': address_info['city'], 
                            'district': address_info['district'],  
                            'country': address_info['country'], 
                            'pincode': address_info['pincode'], 
                            'period_of_stay': address_info['period_of_stay'], 
                            'address_type': address_info['address_type']                   
                        }                                        
                    
                    #if locationData and address_info['id'] != None:
                    if locationData and isinstance(address_info, dict) and address_info.get('id') is not None:                      
                        #print(locationData)
                        LocationUser = Location.objects.get(user_id=benefactor_user_id,pk=address_info['id'])          
                        serializerLoc = LocationSerializer(LocationUser, data=locationData, partial=True)
                             
                        if serializerLoc.is_valid(): 
                           # Save the location                
                           serializerLoc.save()
                           print("User Location")  
            
            #print("coapplicantUser", data['co_applicant_details'])
            #print("coapplicantUser_id",data['co_applicant_details']['user_id'])       
            #update the coapplicant data 
            CoApplicantLocData = [] 
            if request.data['co_applicant_details']:         
                coapplicantUser = CustomUser.objects.get(pk=data['co_applicant_details']['user_id'])                
                # Serialize the request data
                
                coapplicantSerializer = CustomUserSerializer(coapplicantUser, data=data['co_applicant_details'], partial=True)
                if coapplicantSerializer.is_valid():
                    # Save the updated benefactor
                    coapplicantSerializer.save()
                    CoApplicantData = coapplicantSerializer.data              

                    for address_type_coap, address_info_coap in data["co_applicant_details"]["address"].items():
                                         
                        if isinstance(address_type_coap, dict) and address_type_coap.get('id') is None:                        
                            locationAddData = {                        
                                'user_id':  benefactor_user_id, 
                                'address_line1':  address_info_coap['address_line1'], 
                                'address_line2':  address_info_coap['address_line2'],  
                                'cur_town': address_info_coap['cur_town'], 
                                'state': address_info_coap['state'], 
                                'city': address_info_coap['city'], 
                                'district': address_info_coap['district'],  
                                'country': address_info_coap['country'], 
                                'pincode': address_info_coap['pincode'], 
                                'period_of_stay': address_info_coap['period_of_stay'], 
                                'address_type': address_info_coap['address_type']                   
                            }
                            
                            # add the new row if new address not exist in location table                       
                            benefctAddLoc = Location.objects.create(**locationAddData)                        
                        else:
                            locationDataCoApp = {                        
                                'address_line1':  address_info_coap['address_line1'], 
                                'address_line2':  address_info_coap['address_line2'],  
                                'cur_town': address_info_coap['cur_town'], 
                                'state': address_info_coap['state'], 
                                'city': address_info_coap['city'], 
                                'district': address_info_coap['district'],  
                                'country': address_info_coap['country'], 
                                'pincode': address_info_coap['pincode'], 
                                'period_of_stay': address_info_coap['period_of_stay'], 
                                'address_type': address_info_coap['address_type']                   
                            }            

                        print("coapplicant_user_id= ", data['co_applicant_details']['user_id']) 
                                         
                        #if locationDataCoApp and address_type_coap['id'] != None:
                        if locationDataCoApp and isinstance(address_type_coap, dict) and address_type_coap.get('id') is not None:                
                            LocationCoApplicantUser = Location.objects.get(user_id=data['co_applicant_details']['user_id'],pk=address_info_coap['id'])          
                            serializerCoApplicantLoc = LocationSerializer(LocationCoApplicantUser, data=locationDataCoApp, partial=True)
                            #print(LocationUser)            
                            if serializerCoApplicantLoc.is_valid(): 
                               # Save the location                
                               serializerCoApplicantLoc.save()
                               CoApplicantLocData = serializerCoApplicantLoc.data
                               print("Location CoapplicantUser") 

            case_info = request.data.get("case_info")
            print("case_info",case_info)
            if case_info:  
                caseModel = Case.objects.get(pk=case_id,benefactor_user_id=data['benefactor']['user_id'])
                # Pass state to serializer when creating the serializer instance
                caseserializer = CaseSerializer(caseModel, data=data['case_info'], partial=True)
              
                if caseserializer.is_valid(raise_exception=True):
                    # Save the case data
                    caseId  = caseserializer.save()
                    print("caseserializer: ")                       
                    
                    # create the casepurpose data                
                    purpose_queries = request.data.get("purpose_queries")
                    #print("purpose_queries: ",purpose_queries)
                    if purpose_queries:
                        print("purpose_name: ",purpose_queries["purpose_name"])
                        question_details = purpose_queries["question_details"]
                        
                        # Loop through each question and answer
                        for caseAnswerData in question_details:
                            question = caseAnswerData["question_text"]
                            answer   = caseAnswerData["answer_text"]
                            #print(f"Question: {question}")
                            #print(f"Answer: {answer}")
                            #print()  # Print an empty line for better readability  
                            casePurposeModel = CasePurpose.objects.get(pk=caseAnswerData['id'], case_id=case_id)                   
                            casePurposeData = {
                                            'purpose_name': purpose_queries['purpose_name'],
                                            'question_text': question,
                                            'answer_text': answer, 
                                            'case_id': case_id,                                      
                                          }
                            # Pass state to serializer when creating the serializer instance
                            casePurposeserializer = CasePurposeSerializer(casePurposeModel, data=casePurposeData, partial=True)
                            
                            if casePurposeserializer.is_valid(raise_exception=True):                           
                                caseId  = casePurposeserializer.save()                       
            
            benefactor_location  = {"address": serializerLoc.data if serializerLoc.data else [] }            
            coapplicant_location = {"address": CoApplicantLocData}
            casePur           = CasePurpose.objects.filter(case_id=case_id)        
            serializerCasePur = CasePurposeSerializer(casePur, many=True)

            casePurposeData =  {
                                "purpose_name": caseserializer.data['purpose'],
                                "question_details": serializerCasePur.data
                                }   
            # updatedData2 = {
            #                 "benefactor":{**serializerUser.data, **benefactor_location},  
            #                 "co_applicant_details": {**coapplicantSerializer.data, **coapplicant_location},
            #                 "case_info":caseserializer.data,
            #                 "purpose_queries":casePurposeData,
            #                 #"case_query":'null',                            
            #                 #"case_evaluation":'null',
            #               }
           
            #return Response(updatedData2, status=status.HTTP_200_OK)
            return Response({'message': 'Case data updated successfully.'}, status=status.HTTP_200_OK)
            #return Response(caseserializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e: 
            print("Failed to create log file " + e.__str__())       
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to update case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def get_ask_query(request, case_id):
    if request.method == 'PUT':
        #server_url = request.build_absolute_uri('/')
        #print("Server URL:", server_url+'media/')       
        data        = request.data
        user        = request.user
        user_id     = user.id
        question_by = user.firstname+' '+user.lastname
        print("case_id", case_id)
        CaseQuery_exists = Case.objects.filter(pk=case_id).exists()
        print("CaseQuery_exists", CaseQuery_exists)
        if CaseQuery_exists:
        
            # Create the case Query data
            caseQueryData = {
                            'question_text': data['question_text'],
                            'question_by': question_by,
                            'state': data['state'], 
                            'question_by_userid': user_id, 
                            'case_id': case_id,                                      
                            }       
            if caseQueryData: 
                # stored the case query data
                casequery = CaseQuery.objects.create(**caseQueryData)
                print("Valid case query data")       
              
            #return Response(casequery.data, status=status.HTTP_200_OK)       
            return Response({'message': 'Case query added successfully'}, status=status.HTTP_200_OK)
        return Response({'Error': 'Invalid case details'}, status=status.HTTP_400_BAD_REQUEST)
     
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def get_answer_query(request,case_id):
    if request.method == 'PUT':
        
        data        = request.data
        user        = request.user
        user_id     = user.id
        answer_by   = user.firstname+' '+user.lastname        
        queryId     = data['query_id']
        print("user_id", user_id)
        # Create the case answer data
        # Check if a CustomUser object with the specified pk exists
        CaseQuery_exists = CaseQuery.objects.filter(pk=queryId,case_id=case_id).exists()
        if CaseQuery_exists:

            caseAnswerData = {
                                'question_text': data['question_text'],
                                'answer_text': data['answer_text'],
                                'answer_by': answer_by,
                                'state': data['state'], 
                                'answer_by_userid': user_id, 
                                'case_id': case_id,                                      
                             }
            print(caseAnswerData)        
            caseQueryModel = CaseQuery.objects.get(pk=queryId,case_id=case_id)
                # Pass state to serializer when creating the serializer instance
            caseserializer = CaseQuerySerializer(caseQueryModel, data=caseAnswerData, partial=True)
                #print(caseserializer)
            if caseserializer.is_valid(raise_exception=True):
                # Save the updated account
                caseId  = caseserializer.save()
                #return Response(caseserializer.data)
                print("Valid case answer data")       
            return Response({'message': 'Case answer updated successfully'}, status=status.HTTP_200_OK)
        return Response({'Error': 'Invalid case details'}, status=status.HTTP_400_BAD_REQUEST)
      
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_case_disbursement(request):
    try:
        if request.method == 'GET':
            #print("ddd", type(request.data))
            data = request.data
            user = request.user
            print("USER: ",user.id)       
            benefactor_user_id = user.id
            request_case_id = request.query_params.get("case_id")  
           
            user_mappings = CustomUser.objects.filter(email=user).first()

            # Check if there are no account mappings for the user
            if not user_mappings:
                return Response({'Error': 'Wrong benefactor details'}, status=status.HTTP_404_NOT_FOUND)
            
            userserializer = CustomUserSerializer(user_mappings, many=False)
            userData = userserializer.data              
            
            cases      = Case.objects.filter(pk=request_case_id)
            serializer = CaseSerializer(cases, many=True)
            Data       = serializer.data
              
            #get the case Disbursement data
            casePur                = CaseDisbursement.objects.filter(case_id=request_case_id)        
            CustomSerializerDisbursement = CustomDisbursementSerializer(casePur, many=True)
                        
            #return Response(serializerLoc.data, status=status.HTTP_200_OK)
            #list = []
            keys_to_remove = ["next_disburse_days", "next_disburse_amt", "next_repay_days", "next_repay_amt"]
            for caseData in Data:         
                   
                caseDataFinal =  {
                                "user_id":caseData['benefactor_user_id'],                                
                                "purpose":caseData['purpose'],                                                                                      
                                "disbursement_schedule": caseData['disbursement_schedule'],
                                "request_amt":caseData['request_amt'], 
                                "approved_amt":caseData['approved_amt'],  
                                "grant_type":caseData['grant_type'],
                                "disbursement_count":caseData['disbursement_count'],
                                "repay_disburs":getDisbursRepayDays(request_case_id),                      
                                "disbursement_details": CustomSerializerDisbursement.data                          
                            }
                caseDataFinal = reArrange_json(caseDataFinal)
                for key in keys_to_remove:
                    if key in caseDataFinal:
                        del caseDataFinal[key]                                            
                #list.append(caseDataFinal)   
            return Response(caseDataFinal, status=status.HTTP_200_OK)
    except Exception as e:      
        print("Failed to create log file " + e.__str__())            
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
        return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

def update_total_disburs_repay_amount(Model, update_column, get_column, amount, pk_id, case_id):
    try:
        total_sum      = 0
        column_data    = 0
        getItiatialCaseData        = Case.objects.filter(pk=case_id).first() 
        prev_total_disburs_repay   = getattr(getItiatialCaseData, update_column)
        print("prev_total_disbursment_repay: ", prev_total_disburs_repay)
        #Model could be disburded or repay
        get_exist_data = Model.objects.filter(case_id=case_id, pk=pk_id).values_list(get_column, flat=True) 
        
        if get_exist_data:
            column_data    =  get_exist_data[0] 
            #print(update_column)
            FinalTotal     = prev_total_disburs_repay + column_data
            
            #updated_total  = Case.objects.filter(pk=case_id).update(update_column=FinalTotal)
            updated_total = Case.objects.filter(pk=case_id).update(**{update_column: FinalTotal})

        # Get the data from db
        getCaseData          = Case.objects.filter(pk=case_id).first()    
        total_disbursment    = getCaseData.total_disbursment 
        repayment_received   = getCaseData.repayment_received
        approved_amt         = getCaseData.approved_amt

        # calculate the dynamic sauto colum
        outstanding_disbursment = approved_amt - total_disbursment
        pending_repayment       = total_disbursment - repayment_received

        getDisbursRepayData = {
        'total_disbursment'       : getCaseData.total_disbursment, 
        'repayment_received'      : getCaseData.repayment_received, 
        'outstanding_disbursment' : outstanding_disbursment,  
        'pending_repayment'       : pending_repayment
        }
        #print(getDisbursRepayData)
        return getDisbursRepayData
    except Exception as e:      
        print("Failed to create log file " + e.__str__())            
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
        return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

def getDisbursRepayDays(case_id):
    try:        
        next_disburse_days = None
        next_repay_days    = None
        next_disburse_amt  = None
        next_repay_amt     = None

        Disbursement = CaseDisbursement.objects.filter(case_id=case_id).first()
        Repayment    = CaseRepayment.objects.filter(case_id=case_id).first()
        #next_disburse_days = the earliest scheduled disbursement from the disbursement plan 
        #that has not disbursed yet. This value could be -ve if the planned date has been missed.
        #next_disburse_amt = the above planned disbursement amount that is yet to be disbursed
        #next_repay_days = similar to disbursement logic above but consider repayment table instead
        #next_repay_amt = similar to disbursement logic above but consider repayment table instead 
        
        #latest_disburs = CaseDisbursement.objects.filter(case_id=case_id, disbursement_status='Disbursed').order_by('-disbursed_date').first()
        
        latest_disbursed = CaseDisbursement.objects.filter(case_id=case_id, disbursement_status='pending').order_by('planned_date').first()

        latest_repay     = CaseRepayment.objects.filter(case_id=case_id, repayment_status='pending').order_by('planned_date').first()

        if latest_disbursed:
            today = date.today()
            print(" ")
            print("today", today)
            print("Planned Date: ", latest_disbursed.planned_date)
            print("ID :", latest_disbursed.id)
            print("CASE ID :", latest_disbursed.case_id)
            print("disbursed_amt :", latest_disbursed.disbursed_amt)
            next_disburse_days = (latest_disbursed.planned_date - today).days
            print("next_disburse_days :", next_disburse_days)
            print("Repay data print below")
            next_disburse_amt  = latest_disbursed.installment_amt          

        if latest_repay:
            today = date.today()
            print(" ")
            print("today", today)
            print("Planned Date: ", latest_repay.planned_date)
            print("ID :", latest_repay.id)
            print("CASE ID :", latest_repay.case_id)
            print("disbursed_amt :", latest_repay.planned_repayment_amt)
            next_repay_days = (latest_repay.planned_date - today).days
            print("========== ")
            next_repay_amt     = latest_repay.planned_repayment_amt           
        
        # Get the case data from db
        getCaseData          = Case.objects.filter(pk=case_id).first()    
        total_disbursment    = getCaseData.total_disbursment 
        repayment_received   = getCaseData.repayment_received
        approved_amt         = getCaseData.approved_amt
        repay_percent        = getCaseData.repay_percent        

        # calculate the dynamic sauto colum
        outstanding_disbursment = approved_amt - total_disbursment
        pending_repayment       = repay_percent - repayment_received
        
        getDisbursRepayDays = {
        'repay_percent'          : getCaseData.repay_percent, 
        'approved_amt'           : getCaseData.approved_amt, 
        'total_disbursment'      : getCaseData.total_disbursment,
        'repayment_received'     : getCaseData.repayment_received, 
        'outstanding_disbursment': outstanding_disbursment,  
        'pending_repayment'      : pending_repayment,
        #'next_disburse_days': f"{next_disburse_days} Days" if next_disburse_days else None, 
        'next_disburse_days': next_disburse_days if next_disburse_days else None, 
        'next_disburse_amt' : next_disburse_amt, 
        #'next_repay_days'   : f"{next_repay_days} Days" if next_repay_days else None, 
        'next_repay_days'   : next_repay_days if next_repay_days else None,  
        'next_repay_amt'    : next_repay_amt
        }
        return getDisbursRepayDays
    except Exception as e:      
        print("Failed to create log file " + e.__str__())            
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
        return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

# Flatten the JSON data
def reArrange_json(data):
    if "repay_disburs" in data:
        repay_disburs = data.pop("repay_disburs")
        data.update(repay_disburs)
    return data
def case_total_sum(Model, update_column, case_id):
    total_sum = 0
    total     = Model.objects.filter(case_id=case_id).aggregate(total_sum=Sum(update_column))
    total_sum = total['total_sum']
    #print("total_sum: ",total_sum)
    return total_sum

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_case_disbursement(request, case_id):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            data    = request.data
            user    = request.user
            user_id = user.id
            print("USER_ID: ",user.id)
            #print(data['case_info'])
            print("case_id: ",case_id)
            #print(data)     

            request_amt           = request.data.get("request_amt")
            disbursement_schedule = request.data.get("disbursement_schedule")
            approved_amt          = request.data.get("approved_amt")
            disbursement_count    = request.data.get("disbursement_count")

            ID                    = request.data.get("id")
            disbursement_details  = request.data.get("disbursement_details")
            request_case_id       = case_id #request.data.get("case_id")
            #created_by           = request.data.get("created_by")
            #updated_by           = request.data.get("updated_by")
            
            if approved_amt:                                        
                # Update the case disbursement 
                updated_count = Case.objects.filter(pk=case_id).update(request_amt=request_amt,disbursement_schedule=disbursement_schedule,approved_amt=approved_amt,disbursement_count=disbursement_count)


            if disbursement_details:        
                
                Disbursement_exists = CaseDisbursement.objects.filter(case_id=request_case_id).exists()
                #print(Disbursement_exists)
                if Disbursement_exists:
                     # Loop through each disbursement details
                     for caseDisburs in disbursement_details:

                        if caseDisburs['disbursement_status'] == 'delete':
                            # Delete all objects that match certain conditions
                            CaseDisbursement.objects.filter(pk=caseDisburs['id']).delete()

                        #if caseDisburs['id'] == None:
                        if isinstance(caseDisburs, dict) and caseDisburs.get('id') is None:  
                            disburAddData = {                                               
                                            "case_id": request_case_id,
                                            "created_by": user_id if user_id else '0',
                                            "planned_date": caseDisburs['planned_date'],
                                            #"disbursed_date": caseDisburs['disbursed_date'],
                                            "installment_amt": caseDisburs['installment_amt'],
                                            #"disbursed_amt": caseDisburs['disbursed_amt'],
                                            #"remaining_amt":caseDisburs['remaining_amt'],
                                            #"tot_disbursed_amt": caseDisburs['tot_disbursed_amt'],
                                            "disbursement_status": caseDisburs['disbursement_status'],
                                            #"disbursement_txn_info": caseDisburs['disbursement_txn_info']                                  
                                            }
                            disburAdd = CaseDisbursement.objects.create(**disburAddData)  
                        else:                              
                            disburUpdateData = {                                               
                            "updated_by": user_id if user_id else '0',
                            "planned_date": caseDisburs['planned_date'] if caseDisburs['planned_date'] else None,
                            "disbursed_date": caseDisburs['disbursed_date'] if caseDisburs['disbursed_date'] else None,
                            "installment_amt": caseDisburs['installment_amt'] if caseDisburs['installment_amt'] else '0.00',
                            "disbursed_amt": caseDisburs['disbursed_amt'] if caseDisburs['disbursed_amt'] else '0.00',
                            "remaining_amt": caseDisburs['remaining_amt'] if caseDisburs['remaining_amt'] else '0.00',
                            "tot_disbursed_amt": caseDisburs['tot_disbursed_amt'] if caseDisburs['tot_disbursed_amt'] else '0.00',
                            "disbursement_status": caseDisburs['disbursement_status'] if caseDisburs['disbursement_status'] else '',
                            "disbursement_txn_info": caseDisburs['disbursement_txn_info'] if caseDisburs['disbursement_txn_info'] else '',                                     
                            }
                            
                        #if disburUpdateData and caseDisburs['id'] != None:
                        if disburUpdateData and caseDisburs['disbursement_status'] != 'delete' and isinstance(caseDisburs, dict) and caseDisburs.get('id') is not None: 
                            DisbursementModel = CaseDisbursement.objects.get(pk=caseDisburs['id'],case_id=request_case_id)
                            # Pass state to serializer when creating the serializer instance
                            DisburSerializer = DisbursementSerializer(DisbursementModel, data=disburUpdateData, partial=True)
                            #print(disburUpdateData)
                            #print(DisburSerializer)
                            if DisburSerializer.is_valid(raise_exception=True):
                                # Save the Disbur data
                                caseId  = DisburSerializer.save()
                                #print(disburUpdateData)
                                print("updated the Disbursement data")                 
                else:
                    # stored the CaseDisbursement data
                    for caseDisburs in disbursement_details:

                        # Loop through each disbursement details      
                        disburData = {                         
                                        "case_id": request_case_id,
                                        "created_by": user_id if user_id else '0',
                                        "planned_date": caseDisburs['planned_date'],
                                        #"disbursed_date": caseDisburs['disbursed_date'],
                                        "installment_amt": caseDisburs['installment_amt'],
                                        #"disbursed_amt": caseDisburs['disbursed_amt'],
                                        #"remaining_amt":caseDisburs['remaining_amt'],
                                        #"tot_disbursed_amt": caseDisburs['tot_disbursed_amt'],
                                        "disbursement_status": caseDisburs['disbursement_status'],
                                        #"disbursement_txn_info": caseDisburs['disbursement_txn_info']                                     
                                      }      
                        disData = CaseDisbursement.objects.create(**disburData)
                        #print(disData)
                print("Added Disbursement data")
            casePur           = CaseDisbursement.objects.filter(case_id=request_case_id)        
            serializerCasePur = CustomDisbursementSerializer(casePur, many=True)

            #return Response(serializerCasePur.data, status=status.HTTP_200_OK)
            return Response({'message': 'case disbursement updated successfully.'}, status=status.HTTP_200_OK)
            #return Response(caseserializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e: 
            print("Failed to create log file " + e.__str__())       
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to update case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_case_repayment(request):
    try:
        if request.method == 'GET':
            #print("ddd", type(request.data))
            data = request.data
            user = request.user
            print("USER: ",user.id)       
            benefactor_user_id = user.id
            request_case_id = request.query_params.get("case_id")  
           
            user_mappings = CustomUser.objects.filter(email=user).first()

            # Check if there are no account mappings for the user
            if not user_mappings:
                return Response({'Error': 'Wrong benefactor details'}, status=status.HTTP_404_NOT_FOUND)
            
            userserializer = CustomUserSerializer(user_mappings, many=False)
            userData = userserializer.data              
            
            cases      = Case.objects.filter(pk=request_case_id)
            serializer = CaseSerializer(cases, many=True)
            Data       = serializer.data
              
            #get the case Disbursement data
            caseRepay                = CaseRepayment.objects.filter(case_id=request_case_id)        
            serializerRepayment = CustomRepaymentAdminSerializer(caseRepay, many=True)
                        
            #return Response(serializerLoc.data, status=status.HTTP_200_OK)
            #list = []   
            keys_to_remove = ["next_disburse_days", "next_disburse_amt", "next_repay_days", "next_repay_amt"]
            for caseData in Data:         
                   
                caseDataFinal =  {
                                "user_id":caseData['benefactor_user_id'],                                
                                "purpose":caseData['purpose'],                                                                                      
                                "repayment_count": caseData['disbursement_schedule'],
                                "request_amt":caseData['request_amt'], 
                                "approved_amt":caseData['approved_amt'],  
                                "grant_type":caseData['grant_type'],
                                #"disbursement_count":caseData['disbursement_count'],
                                "repay_percent":caseData['repay_percent'],
                                "repay_plan":caseData['repay_plan'],     
                                "repayment_count":caseData['repayment_count'],
                                "repay_disburs":getDisbursRepayDays(request_case_id),
                                "repayment_details": serializerRepayment.data                          
                            }
                caseDataFinal = reArrange_json(caseDataFinal)
                for key in keys_to_remove:
                    if key in caseDataFinal:
                        del caseDataFinal[key]                                             
                #list.append(caseDataFinal)   
            return Response(caseDataFinal, status=status.HTTP_200_OK)
    except Exception as e:      
        print("Failed to create log file " + e.__str__())            
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
        return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_case_repayment(request, case_id):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            data    = request.data
            user    = request.user
            user_id = user.id
            print("USER_ID: ",user.id)
            #print(data['case_info'])
            print("case_id: ",case_id)
            #print(data)  

            repayment_details    = request.data.get("repayment_details")
            request_case_id      = case_id #request.data.get("case_id")
            created_by           = request.data.get("created_by")
            updated_by           = request.data.get("updated_by")

            #request_amt          = request.data.get("request_amt")
            #approved_amt         = request.data.get("approved_amt")
            repay_plan           = request.data.get("repay_plan")
            grant_type           = request.data.get("grant_type")
            repayment_count      = request.data.get("repayment_count")
            repay_percent        = request.data.get("repay_percent")
            update_fields = {
                            "repay_plan": repay_plan,
                            "repayment_count": repayment_count,
                            "repay_percent": repay_percent,
                            }

            if grant_type is not None:
                   update_fields["grant_type"] = grant_type

            if repay_percent:                                        
                # Update the case disbursement 
                #updated_count = Case.objects.filter(pk=case_id).update(repay_plan=repay_plan,repayment_count=repayment_count,repay_percent=repay_percent,grant_type=grant_type)
                updated_count = Case.objects.filter(pk=case_id).update(**update_fields)
        
            if repayment_details:        
                
                repayment_exists = CaseRepayment.objects.filter(case_id=request_case_id).exists()
                #print(repayment_exists)
                if repayment_exists:
                     # Loop through each disbursement details
                     for caseRepay in repayment_details:

                        
                        if caseRepay['repayment_status'] == 'delete':
                            # Delete all objects that match certain conditions
                            CaseRepayment.objects.filter(pk=caseRepay['id']).delete()

                        #if caseDisburs['id'] == None:
                        if isinstance(caseRepay, dict) and caseRepay.get('id') is None:      
                            caseRepayAddData = {                         
                                            "case_id": request_case_id,
                                            "created_by": created_by if created_by else '0',
                                            "planned_date": caseRepay['planned_date'] if caseRepay['planned_date'] else None,
                                            "repayment_date": caseRepay['repayment_date'] if caseRepay['repayment_date'] else None,
                                            "planned_repayment_amt": caseRepay['planned_repayment_amt'],
                                            "actual_repayment_amt": caseRepay['actual_repayment_amt'],
                                            "outstanding_amt":caseRepay['outstanding_amt'],
                                            "tot_repayed_amt": caseRepay['tot_repayed_amt'],
                                            "repayment_status": caseRepay['repayment_status'],
                                            "repayment_txn_info": caseRepay['repayment_txn_info']                
                                            }
                            repayAdd = CaseRepayment.objects.create(**caseRepayAddData)       
                        else:
                             repayUpdateData = {                                               
                                                "updated_by": updated_by if updated_by else '0',
                                                "planned_date": caseRepay['planned_date'],
                                                "repayment_date": caseRepay['repayment_date'],
                                                "planned_repayment_amt": caseRepay['planned_repayment_amt'],
                                                "actual_repayment_amt": caseRepay['actual_repayment_amt'],
                                                "outstanding_amt":caseRepay['outstanding_amt'],
                                                "tot_repayed_amt": caseRepay['tot_repayed_amt'],
                                                "repayment_status": caseRepay['repayment_status'],
                                                "repayment_txn_info": caseRepay['repayment_txn_info']                                     
                                                }
                             
                                                                               
                        if repayUpdateData and caseRepay['repayment_status'] != 'delete' and isinstance(caseRepay, dict) and caseRepay.get('id') is not None: 
                            RepaymentModel = CaseRepayment.objects.get(pk=caseRepay['id'],case_id=request_case_id)
                            # Pass state to serializer when creating the serializer instance
                            RepaySerializer = RepaymentAdminSerializer(RepaymentModel, data=repayUpdateData, partial=True)
                            #print(caseserializer)
                            if RepaySerializer.is_valid(raise_exception=True):
                                # Save the Disbur data
                                caseId  = RepaySerializer.save()
                                #print(repayUpdateData)
                                print("updated the Disbursement data")                          
                        
                else:
                    # stored the CaseDisbursement data
                    for caseRepay in repayment_details:

                        # Loop through each disbursement details      
                        caseRepayData = {                         
                                        "case_id": request_case_id,
                                        "created_by": created_by if created_by else '0',
                                        "planned_date": caseRepay['planned_date'],
                                        "repayment_date": caseRepay['repayment_date'],
                                        "planned_repayment_amt": caseRepay['planned_repayment_amt'],
                                        "actual_repayment_amt": caseRepay['actual_repayment_amt'],
                                        "outstanding_amt":caseRepay['outstanding_amt'],
                                        "tot_repayed_amt": caseRepay['tot_repayed_amt'],
                                        "repayment_status": caseRepay['repayment_status'],
                                        "repayment_txn_info": caseRepay['repayment_txn_info']                
                                      }      
                        disData = CaseRepayment.objects.create(**caseRepayData)
                        #print(disData)
                print("Added Disbursement data")
            caseRepay           = CaseRepayment.objects.filter(case_id=request_case_id)        
            RepaySerializer = CustomRepaymentAdminSerializer(caseRepay, many=True)

            return Response(RepaySerializer.data, status=status.HTTP_200_OK)
            #return Response(caseserializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e: 
            print("Failed to create log file " + e.__str__())       
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to update case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def track_disbursement(request, case_id):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            data    = request.data
            user    = request.user
            user_id = user.id          
            print("case_id: ",case_id)
            #print(data)

            ID = request.data.get("id")
            disbursed_amt                   = request.data.get("disbursed_amt")
            request_case_id                 = case_id #request.data.get("case_id")
            request_disbursed_date          = request.data.get("disbursed_date")
            request_disbursed_amt           = request.data.get("disbursed_amt")
            request_disbursed_amt           = Decimal(str(request_disbursed_amt))
            request_disbursement_txn_info   = request.data.get("disbursement_txn_info")
            
            if request.data:
                if not request_disbursed_amt:
                    return Response({'Error': 'Disbursement amount is required'}, status=status.HTTP_400_BAD_REQUEST)        
                
                Disbursement_exists_data = CaseDisbursement.objects.filter(pk=ID, case_id=request_case_id)               
                if Disbursement_exists_data:
                    # Get the data from db
                    #caseData = get_object_or_404(Case, pk=case_id)
                    getCaseData          = Case.objects.filter(pk=request_case_id).first()    
                    total_disbursment    = getCaseData.total_disbursment 
                    repayment_received   = getCaseData.repayment_received
                    approved_amt         = getCaseData.approved_amt    
                    request_amt          = getCaseData.request_amt
                    print("approved_amt: ",approved_amt)
                    print("total_disbursment: ",total_disbursment)
                    
                    final_total_disbursment = total_disbursment + request_disbursed_amt
                    print("Final_total_disbursment: ",final_total_disbursment)

                    #if final_total_disbursment <= approved_amt:                        
                    # calculate the total of dynamic column
                    outstanding_disbursment = approved_amt - total_disbursment
                    pending_repayment       = total_disbursment - repayment_received

                    db_total_disbursment = case_total_sum(CaseDisbursement, 'disbursed_amt', request_case_id)
                    print("db_total_disbursment: ",db_total_disbursment)
                    for disbursement in Disbursement_exists_data:
                        
                        db_disbursed_amt          = disbursement.disbursed_amt
                        db_remaining_amt          = disbursement.remaining_amt
                        db_tot_disbursed_amt      = disbursement.tot_disbursed_amt                             
                        db_disbursement_status    = disbursement.disbursement_status  
                        
                        if db_total_disbursment == 0:                           
                            update_tot_disbursed_amt  = request_disbursed_amt
                            update_remaining_amt      = approved_amt - request_disbursed_amt
                        else:
                            update_tot_disbursed_amt  = db_total_disbursment + request_disbursed_amt
                            update_remaining_amt      = outstanding_disbursment - request_disbursed_amt                                        
                        #print("outstanding_disbursment :",outstanding_disbursment)
                        #print("update_remaining_amt :",update_remaining_amt)

                        disburUpdateData = {                                       
                                            "remaining_amt":update_remaining_amt if outstanding_disbursment > 0 else 0,
                                            "tot_disbursed_amt": update_tot_disbursed_amt,
                                            "disbursement_status": 'Disbursed',
                                            "disbursed_date": request_disbursed_date, 
                                            "disbursed_amt": request_disbursed_amt,  
                                            "disbursement_txn_info": request_disbursement_txn_info,                                                                                 
                                           }

                        DisbursementModel = CaseDisbursement.objects.get(pk=ID,case_id=request_case_id)
                        # Pass state to serializer when creating the serializer instance
                        DisburSerializer = DisbursementSerializer(DisbursementModel, data=disburUpdateData, partial=True)
                        #print(caseserializer)
                        if DisburSerializer.is_valid(raise_exception=True):
                            # Save the Disbur data
                            caseId  = DisburSerializer.save()
                            #print(disburUpdateData)
                            Result = update_total_disburs_repay_amount(CaseDisbursement,'total_disbursment','disbursed_amt', request_disbursed_amt, ID, request_case_id)
                            # Get the last record from the table with a where condition                          
                            if outstanding_disbursment == 0:
                                update_case_status = 'repayment'                               
                                #Update the case status if all repayment is done
                                updated_count = Case.objects.filter(pk=request_case_id).update(approval_status=update_case_status)
                                print("updated the Disbursement data")              
                     
                    casePur           = CaseDisbursement.objects.filter(pk=ID,case_id=request_case_id)        
                    serializerCasePur = CustomDisbursementSerializer(casePur, many=True)
                    return Response(serializerCasePur.data, status=status.HTTP_200_OK)                    
                    #else:               
                    #    return Response({'Error': 'Total Disbursed amount is greater than approved amount.'}, status=status.HTTP_400_BAD_REQUEST)
                else:               
                    return Response({'Error': 'Requested disburse data not found in database.'}, status=status.HTTP_400_BAD_REQUEST)        
            else:               
                return Response({'Error': 'Request data is empty'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e: 
            print("Failed to create log file " + e.__str__())       
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to update case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)

def track_disbursement_June2024(request, case_id):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            data    = request.data
            user    = request.user
            user_id = user.id          
            print("case_id: ",case_id)
            #print(data)
            
            ID = request.data.get("id")
            disbursed_amt = request.data.get("disbursed_amt")
            request_case_id      = case_id #request.data.get("case_id")
            request_disbursed_date      = request.data.get("disbursed_date")
            request_disbursed_amt      = request.data.get("disbursed_amt")
            request_disbursement_txn_info      = request.data.get("disbursement_txn_info")
            
            if request.data:
                if not request_disbursed_amt:
                    return Response({'Error': 'Disbursement amount is required'}, status=status.HTTP_400_BAD_REQUEST)        
                
                Disbursement_exists_data = CaseDisbursement.objects.filter(pk=ID, case_id=request_case_id)               
                if Disbursement_exists_data:

                    current_record = get_object_or_404(CaseDisbursement, pk=ID)
                    print("current_record:", current_record)
                    previous_record = (CaseDisbursement.objects
                       .filter(case_id=case_id, created_time__lt=current_record.created_time)
                       .exclude(pk=ID)
                       .order_by('-created_time')
                       .first())            
                   
                    if previous_record is None:
                        previous_record = (CaseDisbursement.objects
                           .filter(pk=ID,case_id=request_case_id)                       
                           .order_by('created_time')
                           .first())            
                        print(" previous_record not available ", previous_record)

                    # For debugging, print the last record
                    print("previous_record:", previous_record)
                    if previous_record:

                        print("previous_disbursed_amt: ",previous_record.disbursed_amt)
                        pre_record_disbursed_amt            = previous_record.disbursed_amt
                        pre_record_remaining_amt            = previous_record.remaining_amt
                        pre_record_tot_disbursed_amt        = previous_record.tot_disbursed_amt               
                        pre_record_disbursement_status      = previous_record.disbursement_status
                        print("pre_record_tot_disbursed_amt :",pre_record_tot_disbursed_amt)
                        print("pre_record_remaining_amt :",pre_record_remaining_amt)

                        for disbursement in Disbursement_exists_data:
                            print("ID disbursement :", disbursement.id)
                            db_disbursed_amt          = disbursement.disbursed_amt
                            db_remaining_amt          = disbursement.remaining_amt
                            db_tot_disbursed_amt      = disbursement.tot_disbursed_amt                             
                            db_disbursement_status    = disbursement.disbursement_status  
                            
                            if pre_record_tot_disbursed_amt == 0 or pre_record_remaining_amt == 0:
                                caseData = get_object_or_404(Case, pk=case_id)
                                approved_amt = caseData.approved_amt
                                #print("approved_amt",approved_amt)
                                update_tot_disbursed_amt  = request_disbursed_amt
                                update_remaining_amt      = approved_amt - request_disbursed_amt
                            else:
                                update_tot_disbursed_amt  = pre_record_tot_disbursed_amt + request_disbursed_amt
                                update_remaining_amt      = pre_record_remaining_amt - request_disbursed_amt
                                            
                            print("update_tot_disbursed_amt :",update_tot_disbursed_amt)
                            print("update_remaining_amt :",update_remaining_amt)

                            disburUpdateData = {                                       
                                                "remaining_amt":update_remaining_amt,
                                                "tot_disbursed_amt": update_tot_disbursed_amt,
                                                "disbursement_status": 'Disbursed',
                                                "disbursed_date": request_disbursed_date, 
                                                "disbursed_amt": request_disbursed_amt,  
                                                "disbursement_txn_info": request_disbursement_txn_info,                                                                                 
                                               }

                            DisbursementModel = CaseDisbursement.objects.get(pk=ID,case_id=request_case_id)
                            # Pass state to serializer when creating the serializer instance
                            DisburSerializer = DisbursementSerializer(DisbursementModel, data=disburUpdateData, partial=True)
                            #print(caseserializer)
                            if DisburSerializer.is_valid(raise_exception=True):
                                # Save the Disbur data
                                caseId  = DisburSerializer.save()
                                print(disburUpdateData)
                                # Get the last record from the table with a where condition
                                last_record = CaseDisbursement.objects.filter(case_id=request_case_id).last()  
                                #update_repayment_status =  'Closed' if last_record.id == ID else 'Paid'
                                if last_record.id == ID and update_remaining_amt == 0:
                                    update_case_status = 'repayment'                               
                                    # Update the case status if all repayment is done
                                    updated_count = Case.objects.filter(pk=request_case_id).update(approval_status=update_case_status)
                                    
                                    print("updated the Disbursement data")              
                        
                        casePur           = CaseDisbursement.objects.filter(pk=ID,case_id=request_case_id)        
                        serializerCasePur = CustomDisbursementSerializer(casePur, many=True)
                        return Response(serializerCasePur.data, status=status.HTTP_200_OK)
                    else:
                        print("No previous records found.")
                        return Response({'Error': 'No previous record found'}, status=status.HTTP_400_BAD_REQUEST)                
                else:               
                    return Response({'Error': 'Requested disburse data not found in database'}, status=status.HTTP_400_BAD_REQUEST)        
            else:               
                return Response({'Error': 'Request data is empty'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e: 
            print("Failed to create log file " + e.__str__())       
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to update case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def track_repayment(request, case_id):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            data    = request.data
            user    = request.user
            user_id = user.id           
            print("case_id: ",case_id)
            #print(data)

            ID = request.data.get("id")
            request_actual_repayment_amt = request.data.get("actual_repayment_amt")
            request_actual_repayment_amt = Decimal(str(request_actual_repayment_amt))
            request_case_id              = case_id #request.data.get("case_id")
            request_repayment_date       = request.data.get("repayment_date")            
            request_repayment_txn_info   = request.data.get("repayment_txn_info")
           
            # For debugging, print the queryset
            #print(previous_records.query)  # Print the raw SQL query for debugging      
     
            if request.data:
                if not request_actual_repayment_amt:
                    return Response({'Error': 'Actual repayment amt is required'}, status=status.HTTP_400_BAD_REQUEST)
                                    
                repayment_existing_data = CaseRepayment.objects.filter(pk=ID, case_id=request_case_id)
                
                if repayment_existing_data:                    

                    #caseData = get_object_or_404(Case, pk=case_id)                                
                    getCaseData             = Case.objects.filter(pk=request_case_id).first()    
                    total_disbursment       = getCaseData.total_disbursment 
                    db_repayment_received   = getCaseData.repayment_received
                    approved_amt            = getCaseData.approved_amt    
                    request_amt             = getCaseData.request_amt

                    final_total_repay = db_repayment_received + request_actual_repayment_amt                   
                    #print("approved_amt: ",approved_amt)
                    #print("final_total_repay: ",final_total_repay) 

                    #if final_total_repay <= approved_amt:

                    # calculate the total of dynamic column
                    outstanding_disbursment = approved_amt - total_disbursment
                    pending_repayment       = total_disbursment - db_repayment_received

                    db_total_repay = case_total_sum(CaseRepayment, 'actual_repayment_amt', request_case_id)
                    #print("db_total_repay: ", db_total_repay)
                   
                    # Loop through each repayment details                       
                    for repay in repayment_existing_data: 

                        db_actual_repayment_amt     = repay.actual_repayment_amt
                        db_outstanding_amt          = repay.outstanding_amt
                        db_tot_repayed_amt          = repay.tot_repayed_amt
                        db_repayment_status         = repay.repayment_status
                        
                        if db_total_repay == 0:                                
                            update_tot_repayed_amt  = request_actual_repayment_amt
                            update_outstanding_amt  = approved_amt - request_actual_repayment_amt
                        else:                                
                            update_tot_repayed_amt  = db_repayment_received + request_actual_repayment_amt
                            update_outstanding_amt  = approved_amt - update_tot_repayed_amt
                           
                        #print("update_outstanding_amt :",update_outstanding_amt)
                        #print("update_tot_repayed_amt :",update_tot_repayed_amt)
                                      
                        repayUpdateData =  {                                       
                                                "actual_repayment_amt":request_actual_repayment_amt,
                                                "outstanding_amt":update_outstanding_amt,
                                                "tot_repayed_amt": update_tot_repayed_amt,
                                                "repayment_status": 'Paid',
                                                "repayment_date": request_repayment_date,                                          
                                                "repayment_txn_info": request_repayment_txn_info,                                                                                 
                                            }
                        print(repayUpdateData)
                        repaymentModel = CaseRepayment.objects.get(pk=ID,case_id=request_case_id)
                        # Pass state to serializer when creating the serializer instance
                        repaySerializer = RepaymentAdminSerializer(repaymentModel, data=repayUpdateData, partial=True)
                        #print(repayUpdateData)
                        if repaySerializer.is_valid(raise_exception=True):
                            # Save the Disbur data
                            caseId  = repaySerializer.save()
                            print("request_actual_repayment_amt", request_actual_repayment_amt)
                            Result = update_total_disburs_repay_amount(CaseRepayment,'repayment_received','actual_repayment_amt', request_actual_repayment_amt, ID, request_case_id)
                            #update_repayment_status =  'Closed' if pending_repayment is Zero 
                            if pending_repayment == 0:
                                update_repayment_status = 'closed'                               
                                # Update the case status if all repayment is done
                                updated_count = Case.objects.filter(pk=request_case_id).update(approval_status=update_repayment_status)
                                             
                            print("updated the repayment data") 

                    caseRepay       = CaseRepayment.objects.filter(pk=ID,case_id=request_case_id)        
                    serializerRepay = CustomRepaymentAdminSerializer(caseRepay, many=True)
                    return Response(serializerRepay.data, status=status.HTTP_200_OK)
                    #else:               
                    #    return Response({'Error': 'Total repay amount is greater than approved amount.'}, status=status.HTTP_400_BAD_REQUEST)
                       
                else:               
                    return Response({'Error': 'Requested repayment data not found.'}, status=status.HTTP_400_BAD_REQUEST)         
            else:               
                return Response({'Error': 'Request data is empty'}, status=status.HTTP_400_BAD_REQUEST)   
        except Exception as e: 
            print("Failed to create log file " + e.__str__())       
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to update case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)

def track_repayment_June2024(request, case_id):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            data    = request.data
            user    = request.user
            user_id = user.id           
            print("case_id: ",case_id)
            #print(data)

            ID = request.data.get("id")
            request_actual_repayment_amt = request.data.get("actual_repayment_amt")
            request_case_id      = case_id #request.data.get("case_id")
            request_repayment_date     = request.data.get("repayment_date")            
            request_repayment_txn_info = request.data.get("repayment_txn_info")

            # Fetch previous records for the given user_id
            previous_records = CaseRepayment.objects.filter(case_id=case_id).exclude(pk=ID).order_by('-created_time')
    
            # For debugging, print the queryset
            #print(previous_records.query)  # Print the raw SQL query for debugging      
     
            if request.data:
                if not request_actual_repayment_amt:
                    return Response({'Error': 'Actual repayment amt is required'}, status=status.HTTP_400_BAD_REQUEST)
                                    
                repayment_existing_data = CaseRepayment.objects.filter(pk=ID, case_id=request_case_id)
                if repayment_existing_data:
                    current_record = get_object_or_404(CaseRepayment, pk=ID)
                    previous_record = (CaseRepayment.objects
                       .filter(case_id=case_id, created_time__lt=current_record.created_time)
                       .exclude(pk=ID)
                       .order_by('-created_time')
                       .first())            
                    print(" ")
                    if previous_record is None:
                        previous_record = (CaseRepayment.objects
                           .filter(pk=ID,case_id=request_case_id)                       
                           .order_by('created_time')
                           .first())            
                        print(" previous_record2", previous_record)

                    # For debugging, print the last record
                    if previous_record:

                        print("previous_actual_repayment_amt: ",previous_record.actual_repayment_amt)
                        pre_record_actual_repayment_amt  = previous_record.actual_repayment_amt
                        pre_record_outstanding_amt       = previous_record.outstanding_amt
                        pre_record_tot_repayed_amt       = previous_record.tot_repayed_amt
                        pre_record_repayment_status      = previous_record.repayment_status                             
                        
                        # Loop through each repayment details                       
                        for repay in repayment_existing_data:                            
                            db_actual_repayment_amt  = repay.actual_repayment_amt
                            db_outstanding_amt       = repay.outstanding_amt
                            db_tot_repayed_amt       = repay.tot_repayed_amt
                            db_repayment_status      = repay.repayment_status
                            
                            if pre_record_tot_repayed_amt == 0 or pre_record_outstanding_amt == 0:
                                caseData = get_object_or_404(Case, pk=case_id)
                                approved_amt = caseData.approved_amt
                                #print("approved_amt",approved_amt) 
                                update_tot_repayed_amt  = request_actual_repayment_amt
                                update_outstanding_amt  = approved_amt - request_actual_repayment_amt
                            else:
                                update_outstanding_amt    = pre_record_outstanding_amt - request_actual_repayment_amt
                                update_tot_repayed_amt    = pre_record_tot_repayed_amt + request_actual_repayment_amt
                               
                            print("update_outstanding_amt :",update_outstanding_amt)
                            print("update_tot_repayed_amt :",update_tot_repayed_amt)
                                          
                            repayUpdateData =  {                                       
                                                    "actual_repayment_amt":request_actual_repayment_amt,
                                                    "outstanding_amt":update_outstanding_amt,
                                                    "tot_repayed_amt": update_tot_repayed_amt,
                                                    "repayment_status": 'Paid',
                                                    "repayment_date": request_repayment_date,                                          
                                                    "repayment_txn_info": request_repayment_txn_info,                                                                                 
                                                }

                            repaymentModel = CaseRepayment.objects.get(pk=ID,case_id=request_case_id)
                            # Pass state to serializer when creating the serializer instance
                            repaySerializer = RepaymentAdminSerializer(repaymentModel, data=repayUpdateData, partial=True)
                            #print(repayUpdateData)
                            if repaySerializer.is_valid(raise_exception=True):
                                # Save the Disbur data
                                caseId  = repaySerializer.save()

                                # Get the last record from the table with a where condition
                                last_record = CaseRepayment.objects.filter(case_id=request_case_id).last()  
                                #update_repayment_status =  'Closed' if last_record.id == ID else 'Paid'
                                if last_record.id == ID and update_outstanding_amt == 0:
                                    update_repayment_status = 'closed'                               
                                    # Update the case status if all repayment is done
                                    updated_count = Case.objects.filter(pk=request_case_id).update(approval_status=update_repayment_status)
                                                 
                                print("updated the repayment data") 

                        caseRepay       = CaseRepayment.objects.filter(pk=ID,case_id=request_case_id)        
                        serializerRepay = CustomRepaymentAdminSerializer(caseRepay, many=True)

                        return Response(serializerRepay.data, status=status.HTTP_200_OK)
                    else:
                        print("No previous records found.")
                        return Response({'Error': 'No previous record found'}, status=status.HTTP_400_BAD_REQUEST)
                else:               
                    return Response({'Error': 'Requested repayment data not found in database'}, status=status.HTTP_400_BAD_REQUEST)         
            else:               
                return Response({'Error': 'Request data is empty'}, status=status.HTTP_400_BAD_REQUEST)   
        except Exception as e: 
            print("Failed to create log file " + e.__str__())       
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to update case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_case_status(request, case_id):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            data    = request.data
            user    = request.user
            user_id = user.id          
            print("user_id: ",user_id)
            #print(data)     

            approval_status    = request.data.get("status")         
            request_case_id    = case_id 
            print("request_case_id: ",request_case_id)             
              
            #Check if a user is exists          
            user = CustomUser.objects.filter(pk=user_id).first() 
            print("user_role: ",user.user_role)       
            if user.user_role == "approver":  
                Disbursement_exists = CaseDisbursement.objects.filter(case_id=request_case_id).exists()                
                if Disbursement_exists or approval_status == 'rejected':                                                  
                   # Update the case disbursement 
                   #print("Disbursement_exists: ",Disbursement_exists)
                   updated_count = Case.objects.filter(pk=request_case_id).update(approval_status=approval_status)
                   return Response({'message': 'case status updated successfully.'}, status=status.HTTP_200_OK)
                else:
                    return Response({'Error': 'Disbursement details are not available. Please create disbursement then try to approve the status.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'Error': 'Benefactor is not approver'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e: 
            print("Failed to create log file " + e.__str__())       
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to update case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_repayment_status(request, case_id):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            data    = request.data
            user    = request.user
            user_id = user.id          
            print("user_id: ",user_id)
          
            approval_status    = request.data.get("status")         
            request_case_id    = case_id 
            print("request_case_id: ",request_case_id)            
              
            #Check if a user is exists          
            user = CustomUser.objects.filter(pk=user_id).first()
            print("user_role: ",user.user_role)                  
            if user.user_role == "approver":  
                Repayment_exists = CaseRepayment.objects.filter(case_id=request_case_id).exists()
                #print(Repayment_exists)
                if Repayment_exists:                                                  
                   # Update the case disbursement 
                   updated_count = Case.objects.filter(pk=request_case_id).update(approval_status=approval_status)
                   return Response({'message': 'case status updated successfully.'}, status=status.HTTP_200_OK)               
                else:
                    return Response({'Error': 'Repayment details are not available. Please create repayment then try to approve the status.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'Error': 'Benefactor is not approver'}, status=status.HTTP_400_BAD_REQUEST)                    
        except Exception as e: 
            print("Failed to create log file " + e.__str__())       
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to update case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def fund_management(request):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            lifetime_disbursement   = 0
            total_repaid            = 0
            fundCorpus              = 0
            pending_repayment       = 0
            repayment_received      = 0
            outstanding_disbursment = 0
            given_away_sum          = 0
            pending_cases           = 0

            # Retrieve the accounts based on the account ID
            account       = Account.objects.filter(account_id=1).first()
            fundCorpus    = account.fund_corpus            
            
            #All Approved Cases(Disbursed, Closed and repayment)
            my_values_impact     = ['closed','approved','disbursement','repayment']
            my_values_active     = ['approved','disbursement','repayment']
            my_values_pending    = ['new', 'verification', 'evaluation', 'approval']
            
            #Cases to date
            cases_to_date        = Case.objects.filter(approval_status__in=my_values_impact).count()
            
            # get total disbustment           
            total_disbursement    = Case.objects.filter(approval_status__in=my_values_impact).aggregate(total=Sum('total_disbursment'))
            if lifetime_disbursement is None:
               lifetime_disbursement = 0           
            lifetime_disbursement =  total_disbursement['total']
            
            # Get Unique Benefactors the cases with the specified statuses           
            cases = Case.objects.filter(approval_status__in=my_values_impact)
            # Get the unique benefactor and coapplicant user IDs
            unique_benefactor_ids = cases.values_list('benefactor_user_id', flat=True).distinct()
            #unique_coapplicant_ids = cases.values_list('coapplicant_user_id', flat=True).distinct()
            #Combine the two sets of IDs and get the unique count
            #unique_user_ids = set(unique_benefactor_ids) | set(unique_coapplicant_ids)
            unique_benefactors = len(set(unique_benefactor_ids))

            #Received in_kind
            repayable_in_kind       = Case.objects.filter(approval_status__in=my_values_impact,grant_type='byKind').aggregate(total=Sum('repay_percent'))
            #Sum the approved_amt field
            repayable_in_kind_total = repayable_in_kind['total']     

            #cases_in_kind       = Case.objects.filter(approval_status__in=my_values_impact,grant_type='byKind')
            #Sum the Repayabl_amount field
            #received_in_kind       = cases_in_kind.aggregate(total_sum=Sum('repay_percent'))['total_sum'] or 0
            #received_in_kind_total = total_repayable_amt

            #Given Away = Sum of Approved Amount - Sum of Repayable amounts where Repayment type <> In Kind
            # Filter the cases based on approval statuses and repayment status
            approved_amt_not_bykind       = Case.objects.filter(approval_status__in=my_values_impact).exclude(grant_type='byKind').aggregate(total=Sum('approved_amt'))
            #Sum the approved_amt field
            total_approved_amt_not_bykind = approved_amt_not_bykind['total'] 

            case_not_byKind          = Case.objects.filter(approval_status__in=my_values_impact).exclude(grant_type='byKind')
            repayable_not_byKind_sum = case_not_byKind.aggregate(total_sum=Sum('repay_percent'))['total_sum'] or 0
            given_away_total         = total_approved_amt_not_bykind - repayable_not_byKind_sum
            
            # Get repaid           
            #Received in Kind =  Sum of Repayable amounts (of post approval cases - disbursement, repayment, closed) where Repayment type = In Kind
            total_repay    = Case.objects.filter(approval_status__in=my_values_impact).aggregate(total=Sum('repayment_received'))
            total_repaid   = total_repay['total']
            if total_repaid is None:
               total_repaid = 0
            #Current Liquidity = Fund Size - Sum of (Actual) Disbursed + Sum of (Actual) Repayments           
            current_liquidity  = fundCorpus -lifetime_disbursement + total_repaid
            
            
            #Pending Repayment = [Repaybale amounts of all active cases where grant type <> in_kind] - Repaid
            #Received in Kind =  Sum of Repayable amounts (of post approval cases - disbursement, repayment, closed) where Repayment type = In Kind
            repaid_not_byKind       = Case.objects.filter(approval_status__in=my_values_active).exclude(grant_type='byKind').aggregate(total=Sum('repayment_received'))
            total_repaid_not_byKind = repaid_not_byKind['total']
            if total_repaid_not_byKind is None:
               total_repaid_not_byKind = 0           
            repay_percent_active_not_byKind       = Case.objects.filter(approval_status__in=my_values_active).exclude(grant_type='byKind').aggregate(total=Sum('repay_percent'))
            total_repay_percent_active_not_byKind = repay_percent_active_not_byKind['total']          
            pending_repayment  = total_repay_percent_active_not_byKind - total_repaid_not_byKind

            #Committed = Sum of Approved - Sum of (actual) Disbursed of all active approved cases
            approved_amt_active          = Case.objects.filter(approval_status__in=my_values_active).aggregate(total=Sum('approved_amt'))
            total_approved_amt_active    = approved_amt_active['total']
            total_disbursement_active    = Case.objects.filter(approval_status__in=my_values_active).aggregate(total=Sum('total_disbursment'))
            lifetime_disbursement_active = total_disbursement_active['total']           
            committed     = total_approved_amt_active - lifetime_disbursement_active

            #Net Commitable = Current Liquidity - Committed + Pending Repayment
            net_commitable  = current_liquidity -committed - pending_repayment
            
            #Active cases
            active_cases   = Case.objects.filter(approval_status__in=my_values_active).count()
           
            #Disbursed
            disbursed_active     = Case.objects.filter(approval_status__in=my_values_active).aggregate(total=Sum('total_disbursment'))
            if disbursed_active is None:
               total_disbursed_active = 0
            total_disbursed_active = disbursed_active['total']
          
          
            #Pending Cases = Count of cases in 'New', 'Verification', 'Evaluation', 'Coordination' state. Do not consider draft
            my_values_pending = ['new', 'verification', 'evaluation', 'approval']
            # Exclude 'Draft' state and filter by the interested states
            pending_cases = Case.objects.filter(approval_status__in=my_values_pending).count()
            
            #Requested Amount
            # Filter the cases with pending statuses and exclude drafts
            requested_amount_pending = Case.objects.filter(approval_status__in=my_values_pending).aggregate(Sum('request_amt'))
            # Get the sum of requested amounts
            requested_amount = requested_amount_pending['request_amt__sum'] if requested_amount_pending['request_amt__sum'] else 0


            data = {
            'fund_corpus'            : fundCorpus, 
            'cases_to_date'          : cases_to_date, 
            'lifetime_disbursement'  : lifetime_disbursement,  
            'unique_benefactors'     : unique_benefactors,
            'received_in_kind'       : repayable_in_kind_total or 0,
            'given_away'             : given_away_total or 0,
            'current_liquidity'      : current_liquidity,
            'committed'              : committed,
            'net_committable'        : net_commitable,
            'active_cases'           : active_cases,
            'approved_amount'        : total_approved_amt_active,
            'disbursed'              : total_disbursed_active,            
            'repaid'                 : total_repaid,
            'pending_repayment'      : pending_repayment,
            'pending_cases'          : pending_cases,
            'requested_amount'       : requested_amount,
            }

            # Convert all float values to int
            for key in data:
                if isinstance(data[key], float):
                    data[key] = int(data[key])
            print(data)
            #print(fundManagement)
            return Response(data, status=status.HTTP_200_OK)
        except Exception as e:      
            print("Failed to create log file " + e.__str__())            
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("failed at line no. " + str(exc_tb.tb_lineno) + " With Error: " + e.__str__())
            return Response({'message': "Failed to create case query " + e.__str__()}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)


def calculate_loan_schedule(loan_amount, annual_interest_rate, loan_term_months, monthly_prepayment):
    monthly_interest_rate = annual_interest_rate / 12 / 100
    monthly_interest_rate = annual_interest_rate / 12 / 100
    #monthly_payment = loan_amount * (monthly_interest_rate * (1 + monthly_interest_rate) ** loan_term_months) / ((1 + monthly_interest_rate) ** loan_term_months - 1)
    monthly_payment = loan_amount / loan_term_months
    schedule = []
    remaining_balance = loan_amount

    original_loan_amount = loan_amount
    original_loan_term_months = loan_term_months
    print("loan_term_months", loan_term_months)
    current_date = datetime.now()
    for month in range(1, loan_term_months + 1):
        #interest_payment = remaining_balance * monthly_interest_rate
        interest_payment = 0
        principal_payment = monthly_payment - interest_payment
        
        new_date = current_date + timedelta(days=30 * month)
        #print(new_date.strftime("%Y-%m-%d"))
        print(month)
        if month <= 5 * 12:  # Apply prepayments only for the first 5 years
            #remaining_balance -= (monthly_payment + monthly_prepayment - interest_payment)
            remaining_balance -= (monthly_payment + monthly_prepayment - interest_payment)            
        else:
            #remaining_balance -= (monthly_payment - interest_payment)
            remaining_balance -= (monthly_payment)
        print("remaining_balance: ",remaining_balance)
        if remaining_balance <= 0:
            # Loan is fully paid, no need to continue calculating the schedule
            loan_term_months = month
            #break

        schedule.append({
            'sequence': month,
            'disbursed_date': new_date.strftime("%Y-%m-%d"),            
            'installment_amt': round(monthly_payment,2),
            #'Interest Payment': round(interest_payment,2),
            #'Principal Payment': round(principal_payment,2),
            #'Prepayment': monthly_prepayment if month <= 5 * 12 else 0,
            'remaining_amt': max(0, round(remaining_balance,2))  # Ensure balance doesn't go negative
            #'tot_disbursed_amt': '' 
        })

         # Calculate total interest savings and total tenure reduced
        original_interest = (monthly_payment * original_loan_term_months) - original_loan_amount
        new_interest = (monthly_payment * loan_term_months) - loan_amount
        interest_savings = original_interest - new_interest
        tenure_reduced_months = original_loan_term_months - loan_term_months

        summary = {
            'Total Interest Savings': interest_savings,
            'Total Tenure Reduced (months)': tenure_reduced_months
        }    
    return schedule, summary