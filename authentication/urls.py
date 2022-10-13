from django.urls import path
from authentication import views

urlpatterns = [
    path('register', views.UserRegisterView.as_view(), name='register'),
    path('login', views.UserLoginView.as_view(), name='login'),
    path('profile', views.UserProfileView.as_view(), name='profile'),
    path('change-password', views.UserChangePasswordView.as_view(),
         name='change password'),
    path('send-reset-password-email', views.UserSendResetPasswordEmailView.as_view(),
         name='reset password email'),
    path('reset-password/<uid>/<token>', views.UserPasswordResetView.as_view(),
         name='reset password'),
]
