from django.urls import path, include
from .views import *

urlpatterns = [
    path('dashboard/',dashboard, name= 'gcp-dashboard'),
    path('findings/',findings, name='gcp-findings'),
]