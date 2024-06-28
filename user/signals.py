# Import necessary modules
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.admin.models import LogEntry, ADDITION
from django.contrib.contenttypes.models import ContentType

# Import necessary models
from .models import CustomUser


#@receiver(post_save, sender=CustomUser)
#def create_account_user_mapping(sender, instance, created, **kwargs):
    #if created and instance.default_account and hasattr(instance, 'state'):
        #state = instance.state
        #print(f"New user created: {instance.email}, with brand name: {instance.default_account}")
        #AccountUserMapping.objects.create(account=instance.default_account, user=instance, status=state)
        #print("AccountUserMapping instance created successfully.")

