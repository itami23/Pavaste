from django.db import models

# Create your models here.
class Target(models.Model):
	url = models.CharField(max_length=50,unique=True,blank=False)

	def __str__(self):
		return self.url


class DirectoryListingResult(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    directory = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.target.url} - {self.directory}"


class DNSEnumerationResult(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    record_type = models.CharField(max_length=10)
    records = models.JSONField()

    def __str__(self):
        return f"{self.target}: {self.record_type}"

class WhawebResult(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    server = models.CharField(max_length=200, blank=True)
    technology = models.CharField(max_length=200, blank=True)
    title = models.CharField(max_length=200, blank=True)
    meta_tags = models.JSONField(blank=True, null=True)
    cookies = models.JSONField(blank=True, null=True)
    headers = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"{self.target.url} - {self.server}"

class CrtshResult(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    common_name = models.CharField(max_length=255)
    issuer_organization = models.CharField(max_length=255)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    def __str__(self):
        return f"{self.target.url} - {self.common_name}"


class SubdomainScanResult(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    subdomain = models.CharField(max_length=255)
    headers = models.JSONField()
    screenshot = models.ImageField(null=True, blank=True)
    nmap_results = models.JSONField(null = True)

    def __str__(self):
        return f"{self.target.url} - {self.subdomain}"


class CrawlerResult(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    robots_results = models.JSONField()
    sitemap_results = models.JSONField()
    css_results = models.JSONField()
    js_results = models.JSONField()
    internal_links = models.JSONField()
    external_links = models.JSONField()
    image_links = models.JSONField()
    crawled_sitemap_links = models.JSONField()
    crawled_js_links = models.JSONField()

    def __str__(self):
        return f"{self.target.url}"

class XssResult(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    url = models.CharField(max_length=255)
    vulnerable = models.BooleanField()
    payload = models.CharField(max_length=255,null=True,blank=True)

    def __str__(self):
        return f"{self.target.url}"


class ClickjackingResult(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    url = models.CharField(max_length=255)
    vulnerable = models.BooleanField()
    poc = models.CharField(max_length=255,null=True,blank=True)

    def __str__(self):
        return f"{self.target.url}"

class DirectoryTraversalresult(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    url = models.CharField(max_length=255)
    vulnerable = models.BooleanField()
    payload = models.CharField(max_length=255,null=True,blank=True)

    def __str__(self):
        return f"{self.target.url}"


