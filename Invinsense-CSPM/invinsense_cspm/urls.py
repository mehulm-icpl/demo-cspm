from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls, name='adimig'),
    path('aws/', include('prowler_app.urls')),
    path('', include('user_management.urls')),
    path('azure/', include('cspm_azure.urls')),
    path('git/', include('git_scanning.urls')),
    path('alibaba/',include('cspm_alibaba.urls')),
    path('gcp/',include('cspm_gcp.urls'))
]