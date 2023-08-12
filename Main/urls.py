from django.urls import path,include
from . import views
urlpatterns = [
    path('',views.main,name="main"),
    path('dirb/',views.index,name='index'),
    path('dnsenum/',views.dns_enumeration,name='dnsenum'),
    path('whatweb_tool/', views.whatweb_tool_view, name='whatweb_tool'),
    path('crtsh/',views.crtsh,name="crtsh"),
    path('subdomainscan/<subdomain_id>/',views.subdomainscan,name="subdomainscan"),
    path('crawler/',views.crawler,name='crawler'),
    path('dashboard/',views.Dashboard.as_view(),name='dashboard'),
    ###################REPORT GENERATING##############################
    path('generate-pdf-report/<int:target_id>/', views.generate_pdf_report, name='generate_pdf_report'),
    ##################################################################
    path('target_details/<target_id>/',views.TargetInfo.as_view(),name='target_details'),
    path('subdomain_details/<subdomain_id>/',views.SubdomainInfo.as_view(),name='subdomain_details'),
]
