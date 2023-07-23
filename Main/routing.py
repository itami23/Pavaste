from django.urls import re_path,path

from . import consumers

websocket_urlpatterns = [
    path("ws/directory_listing/", consumers.DirectoryListingConsumer.as_asgi()),
    path('ws/dns_enumerate/', consumers.DNSEnumerationConsumer.as_asgi()),
    path('ws/whatweb_tool/', consumers.WhatWebConsumer.as_asgi()),
]