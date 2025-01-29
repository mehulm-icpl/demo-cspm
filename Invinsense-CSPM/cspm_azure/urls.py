from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from prowler_app import views
from user_management import views
from cspm_azure import views

urlpatterns = [
    path('dashboard/',views.azure_dashboard,name='azure-dashboard'),
    path('findings/',views.azure_findings,name='azure-findings'),
    path('findings/level-good/',views.findings_good, name='findings-good'),
    path('findings/level-warning/',views.findings_warning, name='findings-warning'), 
    path('findings/level-danger/',views.findings_danger, name='findings-danger'),
    path('dashboard/number-of-cloud-profiles/',views.azure_cloud_profiles, name='azure-profiles'),
]