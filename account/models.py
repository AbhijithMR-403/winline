from django.db import models

# Create your models here.

class Account(models.Model):
    ACCOUNT_TYPES = (
        ('advertiser', 'Advertiser'),
        ('partners', 'Partners'),
        ('vendors', 'Vendors'),
    )
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    )

    account_id = models.AutoField(primary_key=True)
    account_type = models.CharField(max_length=20, choices=ACCOUNT_TYPES)
    company_name = models.CharField(max_length=100)
    legal_entity_name = models.CharField(max_length=100)
    #address_line1 = models.CharField(max_length=255)
    #address_line2 = models.CharField(max_length=255, blank=True, null=True)
    #district = models.CharField(max_length=100)
    #city = models.CharField(max_length=100)
    #state = models.CharField(max_length=100)
    #country = models.CharField(max_length=100)
    #pincode = models.CharField(max_length=20)
    org_contact_number = models.CharField(max_length=20, null=True, blank=True)
    primary_contact_name = models.CharField(max_length=100, null=True, blank=True)
    primary_contact_number = models.CharField(max_length=20, null=True, blank=True)
    primary_contact_email = models.EmailField(max_length=255, null=True, blank=True)
    org_website = models.URLField(max_length=200, null=True, blank=True)
    GSTIN = models.CharField(max_length=20, null=True, blank=True)
    #billing_address = models.TextField()
    #shipping_address = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    fund_corpus = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    company_logo = models.ImageField(upload_to="images/", null=True, blank=True)

    class Meta:     #you have to add abstract class
        #abstract = True
        db_table = "account"

    def __str__(self):
        return self.company_name  
