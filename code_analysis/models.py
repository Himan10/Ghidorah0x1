import uuid
from django.db import models
from users_auth.models import GhidorahUser
from .storage import user_directory_path, UserDirectoryFileSystemStorage

class GhidorahCodeAnalysisModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(GhidorahUser, on_delete=models.CASCADE)
    uploaded_file = models.FileField(
        upload_to=user_directory_path, 
        storage=UserDirectoryFileSystemStorage()
    )
    directory_path = models.CharField(max_length=255, null=True, blank=True)
    snyk_results = models.JSONField(null=True, blank=True)
    snyk_rule_ids = models.JSONField(null=True, blank=True)
    semgrep_results = models.JSONField(null=True, blank=True)
    semgrep_check_ids = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"CodeAnalysis {self.id} by {self.user}"
