from django import forms
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from account.models import Account
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
import datetime

class CustomUserManager(BaseUserManager):
    search_fields = ('email',)

    def create_user(self, email, firstname, lastname, password=None):
        print("Entered Create User")
        if not email:
            raise ValueError('Users must have an email address')
        if not firstname:
            raise ValueError('Users must have a first name')
        if not lastname:
            raise ValueError('Users must have a last name')

        email = self.normalize_email(email)
        user = self.model(email=email, firstname=firstname, lastname=lastname)

        if password:
            user.password = make_password(password)  
        user.save(using=self._db)
        return user

    def create_superuser(self, email, firstname, lastname, password):
        user = self.create_user(email=email, firstname=firstname, lastname=lastname, password=password)
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user

class CustomUser(AbstractBaseUser, PermissionsMixin):
    USER_ROLES = (   
        ('benefactor', 'Benefactor'),
        ('requestor', 'Requestor'),     
        ('coordinator', 'Coordinator'),
        ('evaluator', 'Evaluator'),
        ('approver', 'Approver'),
    )
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    )
    gender_status = [
        ('M','Male'),
        ('F','Female'),
    ]
    MARITAL_STATUS_CHOICES = (
        (' ', 'Blank'),
        ('married', 'Married'),
        ('single', 'Unmarried'), 
        ('widowed', 'Widowed'),   
        ('separated', 'Separated'),   
        ('divorced', 'Divorced'),   
        ('other', 'Other'),          
    )
    firstname = models.CharField(max_length=100)
    lastname = models.CharField(max_length=100)
    gender = models.CharField(max_length = 1,choices = gender_status,blank=True,null=True)
    dob = models.DateField(max_length=10, blank=True,null=True, verbose_name = 'Dob [Age]')
    date_joined = models.DateField(default=datetime.date.today)   
    email = models.EmailField(max_length=255, blank=True, null=True)
    phoneno = models.CharField(max_length=12, unique=True)
    #profile_pic = models.ImageField(upload_to="profile_pic/", null=True, blank=True)
    profile_pic = models.CharField(max_length=255, blank=True, null=True)
    nationality = models.CharField(max_length=20, null=True, blank=True)
    religion = models.CharField(max_length=20, null=True, blank=True)
    marital_status = models.CharField(max_length=30, null=True, blank=True)
    highest_education = models.CharField(max_length=255, null=True, blank=True, verbose_name = '[Nature of Occupation:]')
    profession = models.CharField(max_length=255, null=True, blank=True)
    identity_proof = models.CharField(max_length=255, null=True, blank=True)    
    identity_proof_copy = models.CharField(max_length=255, blank=True, null=True)
    address_proof = models.CharField(max_length=255, null=True, blank=True)    
    address_proof_copy = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=10,  choices=STATUS_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    default_account = models.ForeignKey(Account,  null=True, blank=True , on_delete=models.CASCADE)
    user_role = models.CharField(max_length=20,null=True, blank=True, choices=USER_ROLES) 
    is_guarantor = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)    
    income_proof = models.CharField(max_length=255, null=True, blank=True)
    income_copy = models.CharField(max_length=255, blank=True, null=True)
    monthly_income = models.DecimalField(max_digits=10, decimal_places=2,default=0.00)
    tot_fam_income = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    tot_dependants = models.CharField(max_length=255, null=True, blank=True)
    cibil_score = models.CharField(max_length=25, null=True, blank=True)
    covenants_risks = models.CharField(max_length=255, null=True, blank=True)
    

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['firstname', 'lastname']

    def save(self, *args, **kwargs):
        is_new = not self.pk
        user = get_user_model()
        if is_new:
            if self.password and self.status and user.is_superuser:
                #self.send_welcome_email(plain_text_password=self.password)
                self.password = make_password(self.password)
        super().save(*args, **kwargs)


    def has_module_perms(self, app_label):
        return self.is_staff
    
    def has_perm(self, perm, obj=None):
        # For simplicity, grant all permissions to superusers
        if self.is_superuser:
            return True
        return False

    def __str__(self):
        return f"{self.email}"

    def get_full_name(self):
        return f"{self.firstname} {self.lastname}"

    def get_short_name(self):
        return self.firstname
    
    def send_welcome_email(self, plain_text_password):
        login_url = "http://127.0.0.1:8000/user/login/"
        send_mail(
            'Your Account Credentials',
            f'Email: {self.email}\nPassword: {plain_text_password}\n\nYou can login at: {login_url}',
            'from@example.com',
            [self.email],
            fail_silently=False,
        )
    class Meta:    
         verbose_name = 'All User'

# Create your models here.
class Location(models.Model):
    DEFAULT_COMMUNICATION_CHOICES = (
        ('Y', 'Yes'),
        ('N', 'No'),        
    )
    DEFAULT_SHIPPING_CHOICES = (
        ('Y', 'Yes'),
        ('N', 'No'),        
    )
    DEFAULT_BILLING_CHOICES = (
        ('Y', 'Yes'),
        ('N', 'No'),        
    )
    ADDRESS_TYPE_CHOICES = (
        ('permanent', 'Permanent'),
        ('temporary', 'Temporary'),        
    )    
    user_id = models.IntegerField(blank=True, null=True)
    account_id = models.IntegerField(blank=True, null=True)
    address_line1 = models.CharField(max_length=255,null=True)
    address_line2 = models.CharField(max_length=255,null=True, blank=True)
    cur_town = models.CharField(max_length=55,null=True, blank=True)    
    state = models.CharField(max_length=55, null=True, blank=True) 
    city = models.CharField(max_length=55, null=True, blank=True) 
    district = models.CharField(max_length=55, null=True, blank=True) 
    country = models.CharField(max_length=55, null=True, blank=True)    
    pincode = models.CharField(max_length=6, null=True, blank=True)
    period_of_stay = models.CharField(max_length=55,null=True, blank=True)         
    address_type = models.CharField(max_length=10, choices=ADDRESS_TYPE_CHOICES)  
    default_shipping_flag = models.BooleanField(default=False)
    default_billing_flag = models.BooleanField(default=False)
    default_communication = models.BooleanField(default=False)  

    class Meta:    
        verbose_name = 'Location'
        unique_together = ('user_id', 'address_type')
        db_table = "location"   
