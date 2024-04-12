from django.shortcuts import render
import random
from .level1 import divide_python_code_into_blocks as block_easy
from .level2 import divide_python_code_into_blocks as block_medium
from .level3 import divide_python_code_into_blocks as block_hard
from .level3 import tokenize_python_code_block as tokenize
from .test import test_python_code
from .models import *
from rest_framework.decorators import api_view
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.db import transaction
from django.core.mail import EmailMessage
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from django.conf import settings 
import jwt
import json
import string 
import random
from django.template import Template, Context
from rest_framework.viewsets import ModelViewSet
from .serializers import *


@api_view(['POST'])
def create_super_user(request):
    if request.method == 'POST':
        password = request.data.get('password')
        email = request.data.get('email')
        if not password or not email:
            return Response({'error': 'Password, and email are required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.create_superuser(email=email, password=password)
            return Response({'message': 'Superuser created successfully.'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class TokenObtainPairView(APIView):
    def post(self, request):
        email = request.data.get("email")
        if email is not None:
            email = email.strip()
        password = request.data.get("password")
        if password is not None:
            password = password.strip()
        user = authenticate(request, email=email, password=password)
        print("user",user)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            message = f"Successfully signed in. If not done by you please change your password."
            # send_mail(
            #     'New Login',
            #     message,
            #     '',
            #     [user.email],
            #     fail_silently=False,
            # )
            return Response({'access_token': access_token,'role':user.role}, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class VerifyTokenView(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        token = request.data.get("token")
        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            decoded_token = jwt.decode(token, settings.SIGNING_KEY, algorithms=[settings.JWT_ALGORITHM])
            return Response({"valid": True, "decoded_token": decoded_token}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({"error": "Token expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

class TokenRefreshView(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        refresh = RefreshToken.for_user(request.user)
        access_token = str(refresh.access_token)
        return Response({'access_token': access_token}, status=status.HTTP_200_OK)

class GetUserDetails(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        try:
            user = request.user
            data = {
                'username' : user.name,
                'email' : user.email,
                'role' : user.role,
            }
            return Response({'data':data},status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

class Signup(APIView):
    def post(self,request):
        username = request.data.get('username')
        email  = request.data.get('email').strip()
        password = request.data.get('password').strip()
        role = request.data.get('role')

        try:
            account = User.objects.create_user(
                name = username,email=email, password=password,role=role
            )
            # send_mail(
            #     'Welcome',
            #     'Account Created Successfully. You can now login.',
            #     '',
            #     [account.email],
            #     fail_silently=False,
            # )
            return Response({"message": "Registration successful"}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordAPIView(APIView):
    def post(self, request):
        data = request.data
        email = data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=404)
        else:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            reset_password_link = f"http://localhost:3000/reset/{uid}/{token}"

            email_template = """
            Hi {{ user.username }},
            Please click the link below to reset your password:
            {{ reset_password_link }}
            """
            template = Template(email_template)
            context = Context({
                'user': user,
                'reset_password_link': reset_password_link,
            })
            print(reset_password_link)
            message = template.render(context)

            # send_mail('Reset your password', message,'', [email])
            return Response({'success': 'Password reset email has been sent.'})

class ResetPasswordAPIView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid token.'}, status=400)
        else:
            if default_token_generator.check_token(user, token):
                return Response({'uidb64': uidb64, 'token': token})
            else:
                return Response({'error': 'Invalid token.'}, status=400)

    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid token.'}, status=400)
        else:
            print(default_token_generator.check_token(user, token))
            if default_token_generator.check_token(user, token):
                new_password = request.data.get('password')
                user.set_password(new_password)
                user.save()
                message = f"Password successfully changed. If not done by you please change your password."
                # send_mail(
                #     'Password Changed',
                #     message,
                #     '',
                #     [user.email],
                #     fail_silently=False,
                # )
                return Response({'success': 'Password has been reset successfully.'})
            else:
                return Response({'error': 'Invalid token.'}, status=400)

class changePassword(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        current_password = request.data.get('currentPassword')
        new_password = request.data.get('newPassword')
        confirm_password = request.data.get('confirmPassword')

        if user.check_password(current_password):
            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                message = f"Password successfully changed. If not done by you please change your password."
                # send_mail(
                #     'Password Changed',
                #     message,
                #     '',
                #     [user.email],
                #     fail_silently=False,
                # )
                return Response({'success': True})
            else:
                return Response({'success': False, 'message': 'New passwords do not match.'})
        else:
            return Response({'success': False, 'message': 'Invalid current password.'})


# Create your views here.

def shuffle_blocks(blocks):
    random.shuffle(blocks)
    return blocks

class shuffle(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self,request):
        user = request.user
        data = request.data
        code = data['code']
        level = data['level']
        name = data['name']
        description = data['description']
        testcases = data['testcases']
        instructions = data['instructions']
        if level == 'EASY':
            new_blocks = block_easy(code)
        elif level == 'MEDIUM':
            new_blocks = block_medium(code)
        elif level == 'HARD':
            blocks = block_hard(code)
            new_blocks = []
            for block in blocks:
                new_blocks.append([tokenize('\n'.join(block))])
        shuffled_blocks = shuffle_blocks(new_blocks)
        print(type(shuffled_blocks))
        test = Test.objects.create(name = name,level = level,description = description,instructions = instructions,code = code,created_by = user)

        if test:
            test.set_test_cases(testcases)
            test.set_shuffled_blocks(shuffled_blocks)
            test.save()
            return Response({'message': 'Test Created...!'}, status=200)


class TestData(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request, *args, **kwargs):
        user = request.user
        tests = Test.objects.all()
        serializer = TestSerializer(tests,many=True)
        return Response({'data': serializer.data}, status=200)

    def post(self,request):
        user = request.user
        id = request.data.get('id')
        test = Test.objects.get(id = id)
        data = {
            'name':test.name,
            'level' : test.level,
            'description' : test.description,
            'testcase' : test.testcases[0],
            'instructions' : test.instructions,
            'shuffled_blocks' : test.get_shuffled_blocks(),
            'created_by' : test.created_by.name,
        }
        return Response({'data': data}, status=200)

class Resultsubmit(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = request.user
        results = Result.objects.filter(user = user)
        serializer = ResultSerializer(results,many=True)
        return Response({'data': serializer.data}, status=200)

    def post(self,request):
        user = request.user
        id = request.data.get('id')
        codeblocks = request.data.get('code')
        code = ""
        code += "'''\n"
        for codeblock in codeblocks:
            for codeline in codeblock:
                code += codeline + "\n"
        test = Test.objects.get(id = id)
        testcases = test.get_test_cases()
        resultmsg = test_python_code(code,testcases)
        result = Result.objects.create(user = user,test=test,result=resultmsg)
        return Response({'resultmsg': resultmsg}, status=200)
