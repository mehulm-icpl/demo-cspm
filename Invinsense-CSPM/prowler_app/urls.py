from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    # ------------- register url --------------
    path('aws-config/', views.aws_config, name='aws_config'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('dashboard/add-new-profile/', views.aws_multiuser_config, name='aws_new_profile'),
    path('dashboard/number-of-cloud-profiles/', views.number_of_cloud_profiles, name='nuber_of_cloud_profiles'),
    path('dashboard/ganrratepdf/', views.dynamic_pdf_ganrate, name='pdf'),
    path('dashboard/scan-history/', views.scan_history_view, name='scan_history_view'),
    path('findings/', views.findings, name='findings'),
    path('findings/status-pass/',views.pass_finding, name = "pass-finding"),
    path('findings/status-fail/',views.fail_finding, name = "fail-finding"),
    path('findings/status-info/',views.info_finding, name = "info-finding"),
    path('findings/severity-low/',views.low_finding, name = "low-finding"),
    path('findings/severity-medium/',views.medium_finding, name = "medium-finding"),
    path('findings/severity-high/',views.high_finding, name = "high-finding"),
    path('findings/severity-critical/',views.critical_finding, name = "critical-finding"),
    path('dashboard/difference/',views.difference_report, name = "difference_report"),
   
]+static(settings.MEDIA_ROOT, doctument_root=settings.MEDIA_URL)


