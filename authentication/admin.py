from django.contrib import admin
from .models import PendingRegistration
 
@admin.register(PendingRegistration)
class PendingRegistrationAdmin(admin.ModelAdmin):
    list_display = ('email', 'created_at')
    search_fields = ('email',) 