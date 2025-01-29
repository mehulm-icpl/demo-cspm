from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('dashboard/', views.git_dashboard, name='git_dashboard'),
    path('dashboard/reposatary-scan', views.git_leaks_data, name='repo'),
    path('dashboard/reposatary-scan/git-scan-history', views.git_scan_history, name='repo_scan_history'),
    path('dashboard/git-dashboard/git-pdf-report', views.got_html_to_pdf, name='git_pdf'),
]