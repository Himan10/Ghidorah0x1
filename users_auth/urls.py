from django.urls import path
from .views import RegisterView, LoginView, AuthenticateScanId

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('authenticate_scan_id/', AuthenticateScanId.as_view(), name='authenticate_scan_id')
]
