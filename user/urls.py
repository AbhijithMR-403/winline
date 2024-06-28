from django.urls import path, include
from .views import *

urlpatterns = [
    #path('create_user/', create_user, name='create_user'),
    path('login/', login_view, name='login'),
    path('social-login/', social_login, name='social_login'),
    path('logout/', logout, name='logout'),
    path('change-password/', change_password, name='change_password'),
    path('password/reset/', forgot_password, name='forgot_password'),
    path('reset-password/<str:uidb64>/<str:token>/', reset_password, name='reset_password'),
]
