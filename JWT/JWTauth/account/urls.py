from django.contrib import admin
from django.urls import path , include
from account.views import UserRegistrationview,UserLoginView,UserProfileView,UserPasswordView
from account.views import UserPasswordResetVeiw,SendPasswordResetEmailView

urlpatterns = [
    path('register/', UserRegistrationview.as_view(),name='register'),
    path('login/', UserLoginView.as_view(),name='login'),
    path('profile/', UserProfileView.as_view(),name='profile'),
    path('changepassword/', UserPasswordView.as_view(),name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(),name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetVeiw.as_view(),name='reset-password'),
]