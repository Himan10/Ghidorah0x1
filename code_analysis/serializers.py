from rest_framework import serializers
from .models import GhidorahCodeAnalysisModel

class CodeAnalysisSerializer(serializers.ModelSerializer):
    """Code analysis serializer"""
    class Meta:
        """Contains all the fileds belong to given model"""
        model = GhidorahCodeAnalysisModel
        fields = '__all__'

class ScanResultsSerializer(serializers.ModelSerializer):
    """Serializer to display scan results in nice format"""

    uploaded_file = serializers.FileField(required=False)
    class Meta:
        """contains model and list of fields to be returned in the response"""
        model = GhidorahCodeAnalysisModel
        fields = ['id', 'uploaded_file', 'created_at', 'user_id', 'directory_path', 'snyk_rule_ids', 'semgrep_check_ids']

class SemgrepResultSerializer(serializers.Serializer):
    """Serializer to expect a specific body in the request"""

    results = serializers.ListField(
        child=serializers.DictField()
    )