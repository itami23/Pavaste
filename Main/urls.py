from django.urls import path,include
from . import views
urlpatterns = [
    path('',views.index,name='index'),
    path('dnsenum/',views.dns_enumeration,name='dnsenum'),
]
