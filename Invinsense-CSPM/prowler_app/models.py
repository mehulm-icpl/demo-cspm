from django.db import models
from django.contrib.auth.models import User

class Awsmodal(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='awsmodal')
    aws_account_id = models.CharField(max_length=100, default=None)

    def __str__(self):
        return f'{self.user.username} Awsmodal'

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pictures/', default='profile_pictures/default.jpg')

    def __str__(self):
        return f'{self.user.username} Profile'
    
class Azuremodal(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='azuremodal')
    azure_tenant_id = models.CharField(max_length=100, default=None)
    
    def __str__(self):
        return f'{self.user.username} Azuremodal'
