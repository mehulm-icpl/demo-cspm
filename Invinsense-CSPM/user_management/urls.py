from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
    path('',views.index, name='home'),
    path('login/', views.user_login, name='login'),
    path('services/', views.services, name='services'),
    path('register/', views.register, name='register'),
    path('dashboard/lockscreen', views.lockscreen, name='lockscreen'),
    path('dashboard/userprofile', views.user_profile, name='user_profile'),
    path('dashboard/edit-profile', views.edit_profile, name='edit_profile'),
    path('logout/', views.userlogout, name='logout'),
    path('error/',views.handler404_usermanagement, name = "error"),
]