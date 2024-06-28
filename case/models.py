from django import forms
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth import get_user_model
from user.models import CustomUser
import datetime

# Create your models here.
class FileUpload(models.Model):
    file = models.FileField(upload_to='purpose/')  

# Create your models here.
class Case(models.Model):

    STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    )
    APPROVAL_STATUS_CHOICES = (       
        ('draft', 'Draft'),
        ('new', 'New'),
        ('verification', 'Verification'),
        ('evaluation', 'Evaluation'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('closed', 'Closed'),
        ('undecided', 'Undecided'),
        ('disbursement', 'Disbursement'),
        ('repayment', 'Repayment'),
        ('other', 'Other'),
    )
    #amount = models.DecimalField(max_digits=10, decimal_places=2) 
    request_amt = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    purpose = models.CharField(max_length=255, null=True, blank=True)    
    short_description = models.TextField(blank=True, null=True, max_length=1000)
    has_guarantor = models.BooleanField(default=False)
    guarantor_user_id = models.IntegerField(default=0, null=True, blank=True )
    guarantor_name = models.CharField(max_length=100, null=True, blank=True) 
    guarantor_phone = models.CharField(max_length=20, null=True, blank=True) 
    guarantor_email = models.CharField(max_length=100, null=True ,blank=True) 
    benefactor_user_id = models.IntegerField(default=0,  null=True, blank=True )
    coapplicant_user_id = models.IntegerField(default=0,  null=True, blank=True)
    referred_by = models.CharField(max_length=55, null=True, blank=True)
    coordinator_user_id = models.IntegerField(default=0, blank=True, verbose_name = '[Coordinator User ID]') 
    grant_type = models.CharField(max_length=55, null=True, blank=True)
    approval_status = models.CharField(max_length=50, choices=APPROVAL_STATUS_CHOICES)
    #rejection_reason = models.TextField(blank=True,null=True) 
    disbursement_schedule = models.CharField(max_length=100, null=True, blank=True) 
    collateral=  models.CharField(max_length=100, null=True, blank=True)
    #list_of_evaluators = models.TextField(blank=True,null=True)    
    #status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    case_submit_date = models.CharField(max_length=20, null=True, blank=True) 
    pending_info = models.BooleanField(default=False)
    approved_amt = models.DecimalField(max_digits=10, decimal_places=2,default=0.00)
    disbursement_count = models.CharField(max_length=50, null=True, blank=True)
    repay_plan = models.CharField(max_length=50, null=True, blank=True)
    repayment_count = models.CharField(max_length=50, null=True, blank=True)
    repay_percent = models.DecimalField(max_digits=10, decimal_places=2,default=0.00) 
    total_disbursment  = models.DecimalField(max_digits=10, decimal_places=2,default=0.00)
    repayment_received = models.DecimalField(max_digits=10, decimal_places=2,default=0.00)    
 
    class Meta:    
        #abstract = True
        db_table = "case"
   


class CaseQuery(models.Model):
    STATE_CHOICES = (
        ('open', 'Open'),
        ('answered', 'Answered'),
        ('verified', 'Verified'),
        ('closed', 'Closed'),
    )
    
    #case_user = models.ForeignKey('user.CustomUser', on_delete=models.CASCADE)  
    case = models.ForeignKey('Case', on_delete=models.CASCADE)    
    question_text = models.CharField(max_length=255, null=True)
    answer_text = models.TextField(blank=True,null=True)    
    supp_docs_list = models.TextField(blank=True,null=True)    
    question_by = models.CharField(max_length=255, blank=True, null=True)
    question_by_userid = models.IntegerField(default=0, blank=True, verbose_name = '[Question By User ID]') 
    answer_by = models.CharField(max_length=255, blank=True, null=True)
    answer_by_userid = models.IntegerField(default=0, blank=True, verbose_name = '[Answerd By User ID]') 
    question_time = models.DateTimeField(auto_now_add=True)
    answer_time = models.DateTimeField(auto_now=True)
    state = models.CharField(max_length=20,  choices=STATE_CHOICES)

    class Meta:
        #abstract = True    
        db_table = "case_query"
        verbose_name = 'Case Querie'

class CasePurpose(models.Model):    
    case = models.ForeignKey('Case', on_delete=models.CASCADE)
    purpose_name = models.CharField(max_length=255, null=True)    
    question_text = models.CharField(max_length=255, null=True)
    answer_text = models.TextField(blank=True,null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:     
        db_table = "case_purpose"


class CaseEvaluation(models.Model): 

    USER_TYPE = (       
        ('coordinator', 'Coordinator'),
        ('evaluator', 'Evaluator'),
        ('approver', 'Approver'),
    )   
    case = models.ForeignKey('Case', on_delete=models.CASCADE)    
    user_type = models.CharField(max_length=20, choices=USER_TYPE)
    user = models.ForeignKey('user.CustomUser', on_delete=models.CASCADE)
    evaluator_notes = models.TextField(blank=True,null=True)
    #notes_updated_date = models.DateTimeField(auto_now=True)
    evaluation_status = models.CharField(max_length=50, null=True)
    latest_action_date = models.DateTimeField(auto_now=True) 
    evaluator_rating = models.TextField(blank=True,null=True)
    approver_decision = models.TextField(blank=True,null=True)    

    class Meta:    
        db_table = "case_evaluation"

class LovSeedData(models.Model):
     
    MANDATORY_CHOICES = (
        ('Y', 'Yes'),
        ('N', 'No'),        
    )
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    )

    INPUT_TYPE_CHOICES = (
        (' ', 'NULL'),
        ('lov', 'LOV'),
        ('radio_button', 'Radio Button'),
        ('checkbox', 'Checkbox'),
        ('textbox', 'Textarea'),
        ('inputbox', 'Inputbox'),
        ('file', 'File'),
        ('radio_button', 'Radio Button'),
    )   

    lov = models.AutoField(primary_key=True)
    lov_parent_code = models.CharField(max_length=100, null=True)    
    lov_code = models.CharField(max_length=100, null=True)
    display_label = models.CharField(max_length=255, null=True)
    input_type =  models.CharField(max_length=30, choices=INPUT_TYPE_CHOICES)
    lov_ref_code = models.CharField(max_length=60, null=True, verbose_name = 'Input Ref Code')
    mandatory = models.CharField(max_length=20, choices=MANDATORY_CHOICES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "lov_seed_data"
        verbose_name = 'Seed Data Lov'

class CaseDisbursement(models.Model): 
   
    case = models.ForeignKey('Case', on_delete=models.CASCADE)
    created_by = models.IntegerField(default=0, blank=True, verbose_name = '[Created By User ID]')     
    created_time = models.DateTimeField(auto_now_add=True)    
    updated_by = models.IntegerField(default=0, blank=True, verbose_name = '[Updated By User ID]') 
    updated_time = models.DateTimeField(auto_now=True)
    installment_amt = models.DecimalField(max_digits=10, decimal_places=2,default=0.00)
    planned_date = models.DateField(null=True, blank=True)    
    disbursed_date = models.DateField(null=True, blank=True) 
    disbursed_amt = models.DecimalField(max_digits=10, decimal_places=2,default=0.00)
    remaining_amt = models.DecimalField(max_digits=10, decimal_places=2,default=0.00)
    tot_disbursed_amt = models.DecimalField(max_digits=10, decimal_places=2,default=0.00) 
    disbursement_status = models.CharField(max_length=50, null=True, blank=True)
    disbursement_txn_info = models.CharField(max_length=80, null=True, blank=True)
    
    class Meta:    
        db_table = "case_disbursement"

class CaseRepayment(models.Model): 
   
    case = models.ForeignKey('Case', on_delete=models.CASCADE)
    created_by = models.IntegerField(default=0, blank=True, verbose_name = '[Created By User ID]')     
    created_time = models.DateTimeField(auto_now_add=True)    
    updated_by = models.IntegerField(default=0, blank=True, verbose_name = '[Updated By User ID]') 
    updated_time = models.DateTimeField(auto_now=True)
    planned_repayment_amt = models.DecimalField(max_digits=10, decimal_places=2,default=0.00)
    planned_date = models.DateField(null=True, blank=True)    
    repayment_date = models.DateField(null=True, blank=True) 
    actual_repayment_amt = models.DecimalField(max_digits=10, decimal_places=2,default=0.00)
    repayment_txn_info = models.CharField(max_length=80, null=True, blank=True)
    outstanding_amt = models.DecimalField(max_digits=10, decimal_places=2,default=0.00)
    tot_repayed_amt = models.DecimalField(max_digits=10, decimal_places=2,default=0.00) 
    repayment_status = models.CharField(max_length=50, null=True, blank=True)
    
    class Meta:    
        db_table = "case_repayment"
   