from django.db import models
from django.contrib.auth.models import User

class UserFolder(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)  # One-to-one relationship with the User model
    folder_id = models.CharField(max_length=255, null=True, blank=True)  # Folder ID to assign to the user

    def __str__(self):
        return f"{self.user.username}'s folder ID: {self.folder_id}"
