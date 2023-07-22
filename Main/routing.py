from django.urls import re_path,path

from . import consumers

websocket_urlpatterns = [
    path("ws/directory_listing/", consumers.DirectoryListingConsumer.as_asgi()),
]