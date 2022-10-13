# Create your views here.
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

from authentication import serializers, renderers


# Generate token manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegisterView(APIView):
    renderer_classes = [renderers.UserRenderer]

    def post(self, request, format=None):
        serializer = serializers.UserRegisterSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        serializer.save()
        # token = get_tokens_for_user(user)
        return Response({'data': serializer.data, 'msg': 'Registration successful'}, status=status.HTTP_201_CREATED)


class UserLoginView(APIView):
    renderer_classes = [renderers.UserRenderer]

    def post(self, request, format=None):
        serializer = serializers.UserLoginSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')

        user = authenticate(email=email, password=password)

        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'access_token': token, 'msg': 'Login successful'}, status=status.HTTP_200_OK)
        else:
            return Response(data={'errors': {'non_field_errors': 'Invalid Credentials'}}, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    renderer_classes = [renderers.UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = serializers.UserProfileSerializer(request.user)

        return Response({'user': serializer.data}, status=status.HTTP_200_OK)


class UserChangePasswordView(APIView):
    renderer_classes = [renderers.UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = serializers.UserChangePasswordSerializer(
            data=request.data, context={'user': request.user})

        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password changed successfully'}, status=status.HTTP_200_OK)


class UserSendResetPasswordEmailView(APIView):
    renderer_classes = [renderers.UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = serializers.UserSendResetPasswordEmailSerializer(
            data=request.data)

        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password reset link send. Please check your email'}, status=status.HTTP_200_OK)


class UserPasswordResetView(APIView):
    renderer_classes = [renderers.UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer = serializers.UserPasswordResetSerializer(
            data=request.data, context={'uid': uid, 'token': token})

        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password reset successfully'}, status=status.HTTP_200_OK)
