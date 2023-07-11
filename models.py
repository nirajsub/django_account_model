from django.db import models
from django.contrib.auth.models import User

class MainUser(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    phone_number = models.IntegerField()
    business_name = models.CharField(max_length=150)
    address = models.CharField(max_length=150)
    logo = models.ImageField(upload_to="Logo", blank=True, null=True)
    bio = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.user.username

class VerificaionCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    email = models.EmailField(max_length=254)
    code = models.CharField(max_length=50)
    date = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)