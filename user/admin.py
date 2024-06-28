from django.contrib import admin
from .models import CustomUser, Location

class CustomUserAdmin(admin.ModelAdmin):
    search_fields = ('email', 'firstname', 'lastname')  # Add 'email', 'firstname', 'lastname'
    list_display = ("id","firstname","lastname", "email",  "phoneno", "gender","nationality","religion","marital_status","highest_education","status")

admin.site.register(CustomUser, CustomUserAdmin)  # Register CustomUser with CustomUserAdmin
#admin.site.register(AccountUserMapping)

class LocationAdmin(admin.ModelAdmin):
  list_display = ("id","user_id","address_line1","state","city", "district",  "pincode", "country","address_type")

admin.site.register(Location, LocationAdmin)