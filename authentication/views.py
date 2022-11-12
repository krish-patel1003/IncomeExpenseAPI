from django.shortcuts import render
from rest_framework import generics
from .serializers import (
    RegisterSerializer, 
    EmailVerificationSerializer,
    LoginSerializer,
    ResetPasswordEmailRequestSerializer,
    SetNewPasswordSerializer,
    LogoutSerializer
)
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from pprint import pprint
import jwt
from django.conf import settings
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import (
    smart_str, force_str,
    smart_bytes,
    DjangoUnicodeDecodeError
)
from django.utils.http import (
    urlsafe_base64_decode,
    urlsafe_base64_encode
)
from rest_framework.permissions import IsAuthenticated


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer, )
    
    def post(self, request):
        user=request.data
        serializer= self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
    
        user_data = serializer.data

        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')
        absolute_url = f"http://{current_site}{relative_link}?token={str(token)}"
        
        email_body = f"Hi {user.username} Use the link below to verify your email. \n{absolute_url}"
        
        data = {
            'email_body':email_body,
            'email_subject':"verify your email",
            'to_email':user.email
        }
        # pprint(data)
        Util.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)
    

class VerifyEmail(APIView):

    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter(
        'token',
        in_ = openapi.IN_QUERY,
        description='Description',
        type=openapi.TYPE_STRING
    )

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        # print("token", token)

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            print("payload:", payload)
            user = User.objects.get(
                id=payload['user_id']
            )

            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({"email": "Successfully activated"}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as err:
            return Response({"error" : "Activation link expired", "ExpiredSignatureError":str(err)}, status=status.HTTP_400_BAD_REQUEST)
        
        except jwt.DecodeError as err:
            return Response({"error": "Invaid token Couldn't decode token", "DecodeErr":str(err)}, status=status.HTTP_400_BAD_REQUEST)

    
class LoginAPIView(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):
        user= request.data
        serializer= self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetView(generics.GenericAPIView):
    
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request).domain
            relative_link = reverse('password-reset-confirm', kwargs={
                'uidb64':uidb64,
                'token':token
            })
            absolute_url = f"http://{current_site}{relative_link}"
            
            email_body = f"Hello,\nUse the link below to reset your password. \n{absolute_url}"
            
            data = {
                'email_body':email_body,
                'email_subject':"Reset Password ",
                'to_email':user.email
            }
            # pprint(data)
            Util.send_email(data)
            return Response({"success":"we have send u a password reset email"}, status=status.HTTP_200_OK)
        else:
            return Response({"Error":"This account doesn't exists"}, status=status.HTTP_400_BAD_REQUEST)

class PasswordTokenCheckAPI(generics.GenericAPIView):

    def get(self, request, uidb64, token):
        
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    {'error':'Token is not valid, please request new one'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            return Response({
                'success':True,
                'message':'Credentials Valid',
                'uidb64':uidb64,
                'token':token
            })

        except DjangoUnicodeDecodeError as err:
            return Response(
                {'error':'Token is not valid, please request new one'},
                status=status.HTTP_401_UNAUTHORIZED
            )

class SetNewPasswordAPIView(generics.GenericAPIView):

    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {
                'success':True,
                'message':'Password Reset Successfull'
            },
            status=status.HTTP_200_OK
        )


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'mssg': 'user logged out'}, status=status.HTTP_204_NO_CONTENT)


class AuthUserAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = User.objects.get(pk=request.user.pk.pk.pj)
        serializer = RegisterSerializer

        return Response(serializer.data)

