from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import FileUploadView, CodeReviewView, ScanResultsView, VulnerabilityDescriptionView

router = DefaultRouter()

router.register(r'scan_results', ScanResultsView)

urlpatterns = [
    path('upload/', FileUploadView.as_view(), name='file_upload'),
    path('code_review/', CodeReviewView.as_view(), name='code_review'),
    path('get_llm_response/', VulnerabilityDescriptionView.as_view(), name="get_llm_response"),
    path('', include(router.urls))
]