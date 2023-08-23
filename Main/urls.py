from django.urls import path,include
from . import views
urlpatterns = [
    path('',views.main,name="main"),
    path('dirb/',views.dirb.as_view(),name='index'),
    path('dnsenum/',views.dns_enumeration.as_view(),name='dnsenum'),
    path('whatweb_tool/', views.whatweb_tool_view.as_view(), name='whatweb_tool'),
    path('crtsh/',views.crtsh.as_view(),name="crtsh"),
    path('subdomainscan/<subdomain_id>/',views.subdomainscan.as_view(),name="subdomainscan"),
    path('crawler/',views.crawler.as_view(),name='crawler'),
    path('dashboard/',views.Dashboard.as_view(),name='dashboard'),
    ###################REPORT GENERATING##############################
    path('generate-pdf-report/<int:target_id>/', views.generate_pdf_report, name='generate_pdf_report'),
    ##################################################################
    path('target_details/<target_id>/',views.TargetInfo.as_view(),name='target_details'),
    path('subdomain_details/<subdomain_id>/',views.SubdomainInfo.as_view(),name='subdomain_details'),
    path('xss/',views.XssSacan.as_view(),name="xssscan"),
    path('clickjacking/',views.ClickjackingScan.as_view(),name="clickjacking"),
    path('dirtraversal/',views.DirectoryTraversalScan.as_view(),name = 'dirtraversal'),
]
