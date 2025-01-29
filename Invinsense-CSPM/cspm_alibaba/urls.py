from django.urls import path, include
from cspm_alibaba.views import *

urlpatterns = [
    path('dashboard/',alibaba_dashboard, name = "alibaba_dashboard"),
    path('findings/',alibaba_findings, name = "alibaba-findings"),
]