from rest_framework import serializers
from .models import *
from django.utils.translation import gettext as _


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','name','password', 'email','role']
        extra_kwargs = {'password': {'write_only': True}}

class TestSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source='created_by.name', read_only=True)
    class Meta:
        model=Test
        fields= '__all__'

class ResultSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source='user.name', read_only=True)
    test = serializers.CharField(source='test.name', read_only=True)
    

    class Meta:
        model = Result
        fields = '__all__'
