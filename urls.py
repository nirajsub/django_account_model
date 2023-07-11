from django.urls import path
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import TokenRefreshView
from .views import *

urlpatterns = [
    path('login/', AdminTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path('login/refresh/', TokenRefreshView.as_view(), name="token_refresh"),
    path('change_password/<str:pk>/', ChangePasswordView.as_view(), name="change_password"),

    path('verify_email', SendVerificationCodeView.as_view(), name="verifyemail"),
    path('verify_code', VerifyCodeView.as_view()),
    path('reset_password/', ResetPasswordView.as_view(), name='forgot_password'),
]
