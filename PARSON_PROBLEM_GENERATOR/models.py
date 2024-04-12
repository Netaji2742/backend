from django.db import models
import uuid
import json
from django.contrib.auth.models import AbstractUser, BaseUserManager,Permission,Group

class CustomUserManager(BaseUserManager):
    def create_user(self,name, email, password,role="user", **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(name=name,username=email,email=email,role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email,email, password, **extra_fields)

class User(AbstractUser):
    name = models.CharField(max_length=255)
    email = models.EmailField(unique = True)
    role = models.CharField(max_length=20, choices=[('user', 'user'), ('admin', 'admin')], default='user')
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name='user permissions',
        blank=True,
        related_name='custom_user_permissions', 
    )
    groups = models.ManyToManyField(
        Group,
        verbose_name='groups',
        blank=True,
        related_name='custom_user_groups',
    )
    objects = CustomUserManager()

    def __str__(self):
        return self.name

class Test(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.TextField()
    level = models.CharField(max_length=20, choices=[('EASY', 'EASY'), ('MEDIUM', 'MEDIUM'), ('HARD', 'HARD')], default='user')
    description = models.TextField()
    testcases = models.TextField()
    instructions = models.TextField()
    code = models.TextField()
    shuffled_blocks = models.TextField()
    created_by = models.ForeignKey(User,on_delete=models.CASCADE,null=True,blank=True)

    def set_shuffled_blocks(self, blocks):
        self.shuffled_blocks = json.dumps(blocks)

    def get_shuffled_blocks(self):
        return json.loads(self.shuffled_blocks) if self.shuffled_blocks else []  

    def set_test_cases(self, testcase):
        self.testcases = json.dumps(testcase)

    def get_test_cases(self):
        return json.loads(self.testcases) if self.testcases else []

class Result(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    test = models.ForeignKey(Test, on_delete=models.CASCADE)
    result = models.TextField()