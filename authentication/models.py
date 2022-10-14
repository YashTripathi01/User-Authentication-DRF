# Create your models here.
from django.db import models
from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser)


# Custom user manager
class UserManager(BaseUserManager):
    def create_user(self, email, name, username, password=None, password2=None):
        """
        Creates and saves a User with the given email, name, username and password.
        """
        if not email:
            raise ValueError('User must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            username=username,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, username, password=None):
        """
        Creates and saves a superuser with the given email, name, username and password.
        """
        user = self.create_user(
            email,
            password=password,
            name=name,
            username=username
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


# Custom user model
class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='email address', max_length=255, unique=True,)
    name = models.CharField(max_length=20)
    username = models.CharField(max_length=25, unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'username']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
