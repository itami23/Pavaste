from django.shortcuts import render,redirect
from django.http import HttpResponse
import json
from .forms import *
from .models import *
from django.views import View

def index(request):
    return render(request, 'Main/index.html')


def dns_enumeration(request):
    return render(request, 'Main/dnsenum.html')

def whatweb_tool_view(request):
    return render(request, 'Main/whatweb_tool.html')

def crtsh(request):
    return render(request, 'Main/crtsh.html')

def subdomainscan(request):
    return render(request, 'Main/subdomainscan.html')

def crawler(request):
    return render(request, 'Main/crawler.html')


def main(request):
    if request.method == 'POST':
        form = URLForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            ###############SAVE THE TARGET TO THE DATABASE################
            if Target.objects.filter(url=url):
                pass
            else :
                target = Target(url=url)
                target.save()
            request.session['url'] = url
            return redirect('index')
    else:
        form = URLForm()

    return render(request, 'Main/main.html', {'form': form})


class Dashboard(View):
    def get(self,request,*args,**kwargs):
        targets = Target.objects.all()
        targets_count = targets.count()

        target_data = []
        for target in targets:
            directory_count = DirectoryListingResult.objects.filter(target=target).count()
            subdomain_count = CrtshResult.objects.filter(target=target).count()
            #open_ports_count = WhawebResult.objects.filter(target=target).count()  # Assuming open ports are stored here
            crawler_result = CrawlerResult.objects.filter(target=target).first()
            url_crawled_count = (
                len(crawler_result.robots_results) +
                len(crawler_result.sitemap_results) +
                len(crawler_result.css_results) +
                len(crawler_result.js_results) +
                len(crawler_result.internal_links) +
                len(crawler_result.external_links) +
                len(crawler_result.image_links) +
                len(crawler_result.crawled_sitemap_links) +
                len(crawler_result.crawled_js_links)
            )

            target_data.append({
                'target': target,
                'directory_count': directory_count,
                'subdomain_count': subdomain_count,
                'url_crawled_count': url_crawled_count,
            })


        context = {
            'target_data' : target_data,
            'targets_count' : targets_count,
        }
        return render(request, "Main/dashboard.html",context)





##############################################REPORT GENERATION#############################
from django.http import HttpResponse
from django.template.loader import get_template
from django.shortcuts import get_object_or_404
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Image
from .models import Target, DirectoryListingResult, DNSEnumerationResult, WhawebResult, CrtshResult, SubdomainScanResult, CrawlerResult
from PIL import Image as PILImage

def generate_pdf_report(request, target_id):
    target = get_object_or_404(Target, pk=target_id)

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{target.url}_report.pdf"'

    # Create a PDF document object
    doc = SimpleDocTemplate(response, pagesize=landscape(letter))
    elements = []

    # Retrieve data from models for the given target
    # ... (same as before)

    # Create a list of data to include in the PDF
    data = [
        ['Target', target.url],
        ['Directory Results', directory_results],
        ['DNS Results', dns_results],
        ['Whaweb Results', whaweb_results],
        ['Crtsh Results', crtsh_results],
        ['Subdomain Scan Results', subdomain_scan_results],
        ['Crawler Results', crawler_results],
        # Add other data here...
    ]

    # Create a table and add the data
    table = Table(data)
    table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), (0.6, 0.6, 0.6))]))  # Set header background color

    # Add the table to the PDF document
    elements.append(table)

    # Add images from SubdomainScanResult
    for result in subdomain_scan_results:
        if result.screenshot:
            pil_image = PILImage.open(result.screenshot.path)
            img = Image(result.screenshot.path, width=300, height=200)
            elements.append(img)

    # Build the PDF document
    doc.build(elements)

    return response

##########################################################################################


