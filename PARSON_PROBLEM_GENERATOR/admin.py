from django.contrib import admin
from .models import *

# Register your models here.

class UserAdmin(admin.ModelAdmin):
    list_display=['id','name','email']

class TestAdmin(admin.ModelAdmin):
    list_display=['id','name','level']

class ResultAdmin(admin.ModelAdmin):
    list_display=['id','user','result']

admin.site.register(Test,TestAdmin)
admin.site.register(Result,ResultAdmin)
admin.site.register(User,UserAdmin)