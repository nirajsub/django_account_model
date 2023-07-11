from django.shortcuts import render
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import generics, permissions, status, filters
from rest_framework.views import APIView
from django.contrib.auth.views import PasswordResetView
from rest_framework import serializers, views, status
from django.contrib.auth import get_user_model
from .serializers import *
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.utils import timezone
User = get_user_model()

# class AdminTokenObtainPairView(TokenObtainPairView):
#     permissions_classes = (AllowAny,)
#     serializer_class = AdminTokenObtainPairSerializer

class AdminTokenObtainPairView(TokenObtainPairView):
    authentication_classes = []  # Disable default authentication classes
    permission_classes = []  # Disable default permission classes
    serializer_class = AdminTokenObtainPairSerializer

class ChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({"message": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)
            except Exception as e:
                return Response({"message": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"message": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

# {
# "email":"your email"
# }
class SendVerificationCodeView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            verification_code = get_random_string(length=6)
            user.password_reset_code = verification_code
            user.save()
            verificationuser = VerificaionCode.objects.create(
                    user = user,
                    email = email,
                    code = verification_code
                )
        except User.DoesNotExist:
            return Response({'message': 'Invalid email.'}, status=400)

        send_mail(
            subject='Password Reset Verification Code',
            message=f'Your verification code is: {verification_code}',
            from_email='your_email@example.com',
            recipient_list=[email],
            fail_silently=False
        )
        return Response({'message': 'Verification code sent.'}, status=200)

#  {
#  "email":"your email,
# "code":"code in mail"
#  }
class VerifyCodeView(APIView):
    def post(self, request):
        email = request.data.get('email')
        verification_code = request.data.get('code')
        codeuser = VerificaionCode.objects.filter(email=email).last()
        try:
            user = User.objects.get(email=email)
            if codeuser.code == verification_code:
                expiration_time = codeuser.date + timezone.timedelta(minutes=5)
                if timezone.now() > expiration_time:
                    return Response({'message': 'Verification code has expired.'}, status=400)
                if codeuser.is_used:
                    return Response({'message': 'Verification code has already been used.'}, status=400)
                return Response({'message': 'Verification code verified.'}, status=200)
            else:
                return Response({'message': 'Invalid verification code.'}, status=400)
        except User.DoesNotExist:
            return Response({'message': 'Invalid email.'}, status=400)

#  {
#  "email":"your email",
# "code":"code in main",
# "password":"your new password"
#  }
class ResetPasswordView(APIView):
    def post(self, request):
        code = request.data.get('code')
        email = request.data.get('email')
        new_password = request.data.get('password')
        try:
            user = User.objects.get(email=email)
            if user:
                verificationuser = VerificaionCode.objects.get(code=code, email=email, user=user)
                if verificationuser:
                    expiration_time = verificationuser.date + timezone.timedelta(minutes=5)
                    if timezone.now() > expiration_time:
                        return Response({'message': 'Verification code has expired.'}, status=400)
                    if verificationuser.is_used:
                        return Response({'message': 'Verification code has already been used.'}, status=400)
                    user.set_password(new_password)
                    user.save()
                    verificationuser.is_used = True
                    verificationuser.save()
                    return Response({'message': 'Password changed successfully.'}, status=200)
                else:
                    return Response({'message': 'Password reset failed due to Outdated verification code.'}, status=400)
            else:
                return Response({'message': 'No user with this email.'}, status=400)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            return Response({'message': 'Invalid password reset link.'}, status=400)