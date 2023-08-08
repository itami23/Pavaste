from django.urls import path,include
from . import views
urlpatterns = [
    path('',views.main,name="main"),
    path('dirb/',views.index,name='index'),
    path('dnsenum/',views.dns_enumeration,name='dnsenum'),
    path('whatweb_tool/', views.whatweb_tool_view, name='whatweb_tool'),
    path('crtsh/',views.crtsh,name="crtsh"),
    path('subdomainscan/',views.subdomainscan,name="subdomainscan"),
    path('crawler/',views.crawler,name='crawler'),
]
