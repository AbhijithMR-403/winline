from django.urls import path
from .views import *




urlpatterns = [
    path('hello/', hello, name='hello'),
    path('about/', about, name='about'),
    path('update/<int:account_id>/', update_account, name='update_account'),
    path('view/', get_account_info, name='get_account_info'),
] 
