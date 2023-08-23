from django.urls import re_path,path

from . import consumers

websocket_urlpatterns = [
    path("ws/directory_listing/", consumers.DirectoryListingConsumer.as_asgi()),
    path('ws/dns_enumerate/', consumers.DNSEnumerationConsumer.as_asgi()),
    path('ws/whatweb_tool/', consumers.WhatWebConsumer.as_asgi()),
    path('ws/crtsh_search/', consumers.CRTSHConsumer.as_asgi()),
    path('ws/subdomain_scan/', consumers.SubdomainScanConsumer.as_asgi()),
    path('ws/crawler/', consumers.CrawlerConsumer.as_asgi()),
    path('ws/xss_scanner/',consumers.XSSScannerConsumer.as_asgi()),
    path('ws/clickjack_scanner/',consumers.ClickjackScannerConsumer.as_asgi()),
    path('ws/directory_traversal_scanner/',consumers.DirectoryTraversalScannerConsumer.as_asgi()),
]