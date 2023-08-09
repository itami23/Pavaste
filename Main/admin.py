from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(Target)
admin.site.register(DirectoryListingResult)
admin.site.register(DNSEnumerationResult)
admin.site.register(WhawebResult)
admin.site.register(CrtshResult)
admin.site.register(SubdomainScanResult)
admin.site.register(CrawlerResult)