from django.shortcuts import render
from django.http import HttpResponse
from rest_framework.decorators import api_view,permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from account.serializer import AccountSerializer
from account.models import Account
from user.models import AccountUserMapping
from rest_framework.response import Response
from rest_framework import status

# Create your views here.


def hello(request):
    return HttpResponse("Hello Sir")

def about(request):
    return HttpResponse("About Sir")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_account(request, account_id):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        try:
            # Retrieve the token from the request
            token = request.headers['Authorization'].split(' ')[1]
            # Retrieve the user associated with the token
            user = Token.objects.get(key=token).user
            # Check if the user is an admin_account
            if user.user_role == 'account_admin':
                try:
                    # Retrieve the account ids associated with the admin_account
                    account_ids = AccountUserMapping.objects.filter(user=user).values_list('account_id', flat=True)
                    # Check if the provided account_id is associated with the admin_account
                    if account_id in account_ids:
                        # Fetch the account object
                        account = Account.objects.get(pk=account_id)
                        # Serialize the request data
                        serializer = AccountSerializer(account, data=request.data, partial=True)
                        if serializer.is_valid():
                            # Save the updated account
                            serializer.save()
                            return Response(serializer.data)
                        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response({'error': 'You do not have permission to edit this account'}, status=status.HTTP_403_FORBIDDEN)
                except Account.DoesNotExist:
                    return Response({'error': 'Account not found'}, status=status.HTTP_404_NOT_FOUND)
            else:
                return Response({'error': 'You do not have permission to edit accounts'}, status=status.HTTP_403_FORBIDDEN)
        except Token.DoesNotExist:
            return Response({'error': 'Invalid or missing authentication token'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response({'error': 'Authentication credentials were not provided'}, status=status.HTTP_401_UNAUTHORIZED)




@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_account_info(request):
    # Retrieve the user's account IDs from AccountUserMapping
    user = request.user
    account_mappings = AccountUserMapping.objects.filter(user=user)
    
    # Check if there are no account mappings for the user
    if not account_mappings:
        return Response({'error': 'User is not associated with any account'}, status=status.HTTP_404_NOT_FOUND)
    
    account_ids = [mapping.account_id for mapping in account_mappings]
    
    # Retrieve the accounts based on the account IDs
    accounts = Account.objects.filter(account_id__in=account_ids)
    
    # Serialize the account data
    serializer = AccountSerializer(accounts, many=True)
    
    return Response(serializer.data)