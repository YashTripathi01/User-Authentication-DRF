from rest_framework import serializers
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from authentication import models
from authentication.utils import Util


class UserRegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = models.User
        fields = ['email', 'username', 'name', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password != password2:
            raise serializers.ValidationError(
                'Password and Confirm Password does not match')

        return attrs

    def create(self, validated_data):
        return models.User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = models.User
        fields = ['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        fields = ['id', 'email', 'username']


class UserChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255,
                                     style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255,
                                      style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = models.User
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')

        if password != password2:
            raise serializers.ValidationError(
                'Password and Confirm Password does not match')

        user.set_password(password)
        user.save()

        return attrs


class UserSendResetPasswordEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = models.User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')

        if models.User.objects.filter(email=email).exists():
            user = models.User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = f'http://localhost:3000/api/users/reset/{uid}/{token}'
            print(link)

            data = {
                'subject': 'Reset password',
                'body': f'Click the following link to reset your password {link}',
                'to_email': user.email
            }

            Util.send_email(data)

            return attrs

        else:
            raise serializers.ValidationError('You are not a registered user')


class UserPasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255,
                                     style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255,
                                      style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = models.User
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')

            decoded_uid = smart_str(urlsafe_base64_decode(uid))
            user = models.User.objects.get(id=decoded_uid)

            if password != password2:
                raise serializers.ValidationError(
                    'Password and Confirm Password does not match')

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError(
                    'Token is not valid or expired')

            user.set_password(password)
            user.save()

            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not valid or expired')
