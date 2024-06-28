from django.contrib import admin
from .models import *
# Register your models here.


#admin.site.register(Account)

class AccountAdmin(admin.ModelAdmin):
  list_display = ("account_id","company_name","legal_entity_name", "account_type",  "primary_contact_name", "primary_contact_number","created_at", "GSTIN")

admin.site.register(Account, AccountAdmin)