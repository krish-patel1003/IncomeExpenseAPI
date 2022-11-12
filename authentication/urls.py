from django.urls import path
from .views import (
    RegisterView,
    VerifyEmail,
    LoginAPIView,
    PasswordTokenCheckAPI,
    RequestPasswordResetView,
    SetNewPasswordAPIView,
    LogoutAPIView,
    AuthUserAPIView
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register', RegisterView.as_view(), name='register'),
    path('email-verify/', VerifyEmail.as_view(), name='email-verify'),
    path('login', LoginAPIView.as_view(), name='login'),
    path('logout', LogoutAPIView.as_view(), name='logout'),
    path('user', AuthUserAPIView.as_view(), name='user'),
]

urlpatterns += [
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('request-reset-password-email', RequestPasswordResetView.as_view(), name='request-reset-password-email'),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete')
]