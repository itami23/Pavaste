from django.shortcuts import render,redirect,get_object_or_404
from django.http import HttpResponse
import json
from .forms import *
from .models import *
from django.views import View
from django.template.loader import get_template
from django.template import Context
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from .models import Target, DirectoryListingResult, DNSEnumerationResult, WhawebResult, CrtshResult, SubdomainScanResult, CrawlerResult
from reportlab.platypus import SimpleDocTemplate, Paragraph, KeepTogether
from reportlab.platypus import Image
from reportlab.platypus import Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, KeepTogether, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch



class dirb(View):
    def get(self,request,*args,**kwargs):
        return render(request, 'Main/index.html')


class dns_enumeration(View):
    def get(self,request,*args,**kwargs):
        return render(request, 'Main/dnsenum.html')


class whatweb_tool_view(View):
    def get(self,request,*args,**kwargs):
        return render(request, 'Main/whatweb_tool.html')  

class crtsh(View):
    def get(self,request,*args,**kwargs):
        return render(request, 'Main/crtsh.html')      

class subdomainscan(View):
    def get(self,request,*args,**kwargs):
        context = {
            'subdomain_id': self.kwargs.get('subdomain_id'),
        }
        return render(request, 'Main/subdomainscan.html',context)

class crawler(View):
    def get(self,request,*args,**kwargs):
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
            return redirect('dashboard')
    else:
        form = URLForm()

    return render(request, 'Main/main.html', {'form': form})


class Dashboard(View):
    """
    View class that renders the dashboard page.

    This class-based view is responsible for rendering the dashboard page,
    which displays summarized information about targets, directory listings,
    subdomains, and URL crawl results.

    Template:
        The dashboard page template should be named 'Main/dashboard.html'
        and should be placed in the appropriate template directory. The template
        should expect a context variable named 'target_data' containing a list of
        dictionaries with target-related information, and a 'targets_count'
        variable with the total number of targets.
    """
    def get(self,request,*args,**kwargs):
        targets = Target.objects.all()
        targets_count = targets.count()

        target_data = []
        for target in targets:
            directory_count = DirectoryListingResult.objects.filter(target=target).count()
            subdomain_count = CrtshResult.objects.filter(target=target).count()
            #open_ports_count = WhawebResult.objects.filter(target=target).count()  # Assuming open ports are stored here
            crawler_result = CrawlerResult.objects.filter(target=target).first()
            if crawler_result : 
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
            else : 
                url_crawled_count = 0

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
def generate_pdf_report(request, target_id):
    """
    Generate a PDF report for a specific target's scan results.

    This function-based view generates a PDF report containing summarized scan
    results for a specific target. The report includes data from various related
    models such as DirectoryListingResult, DNSEnumerationResult, WhawebResult,
    CrtshResult, SubdomainScanResult, and CrawlerResult.
    """
    target = Target.objects.get(id=target_id)
    font_size = 8

    # Retrieve data from related models
    try : 
        directory_results = DirectoryListingResult.objects.filter(target=target)
        dns_results = DNSEnumerationResult.objects.filter(target=target)
        whaweb_results = WhawebResult.objects.filter(target=target)
        crtsh_results = CrtshResult.objects.filter(target=target)
        subdomain_scan_results = SubdomainScanResult.objects.filter(target=target)
        crawler_results = CrawlerResult.objects.filter(target=target)

        # Create a PDF response
        response = HttpResponse(content_type='application/pdf')
        
        # Set the filename as the target name
        pdf_filename = f"{target.url.replace('://', '_')}_report.pdf"
        response['Content-Disposition'] = f'attachment; filename="{pdf_filename}"'

        # Create a PDF document using reportlab
        doc = SimpleDocTemplate(response, pagesize=letter)
        story = []

        # Add title
        story.append(Paragraph(f"Report for Target: {target.url}", getSampleStyleSheet()['Title']))

        # Add directory listing results
        story.append(Paragraph("Directory Listing Results:", getSampleStyleSheet()['Heading1']))
        for directory_result in directory_results:
            story.append(Paragraph(f"Directory: {directory_result.directory}", getSampleStyleSheet()['Normal']))

        # Add DNS enumeration results
        story.append(Paragraph("DNS Enumeration Results:", getSampleStyleSheet()['Heading1']))
        dns_data = [['Record Type', 'Records']]
        for dns_result in dns_results:
            record_type = dns_result.record_type
            if record_type in ['AAAA', 'NS', 'MX', 'SOA', 'TXT']:
                records = '\n'.join(dns_result.records)  # Use '\n' for line breaks
            else:
                records = ', '.join(dns_result.records)
            dns_data.append([record_type, records])

        font_size = 8
        dns_table = Table(dns_data, colWidths=[70, 450], hAlign='LEFT')
        dns_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0c7300')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, 0), font_size),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), '#FFFFFF'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), font_size),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, '#000000'),
            ('WORDWRAP', (0, 1), (-1, -1), True),  # Enable word wrapping for the data rows

        ]))

        story.append(dns_table)


        # Add Whaweb Results section
        story.append(Paragraph("Whatweb Results:", getSampleStyleSheet()['Heading1']))
        for whaweb_result in whaweb_results:
            story.append(Paragraph("Server:", getSampleStyleSheet()['Heading4']))
            story.append(Paragraph(whaweb_result.server, getSampleStyleSheet()['Normal']))
            story.append(Paragraph("Technology:", getSampleStyleSheet()['Heading4']))
            story.append(Paragraph(whaweb_result.technology, getSampleStyleSheet()['Normal']))
            story.append(Paragraph("Title:", getSampleStyleSheet()['Heading4']))
            story.append(Paragraph(whaweb_result.title, getSampleStyleSheet()['Normal']))

            # Display Meta Tags
            story.append(Paragraph("Meta Tags:", getSampleStyleSheet()['Heading4']))
            for key, value in whaweb_result.meta_tags.items():
                story.append(Paragraph(f"{key}: {value}", getSampleStyleSheet()['Normal']))

            # Display Cookies
            story.append(Paragraph("Cookies:", getSampleStyleSheet()['Heading4']))
            for key, value in whaweb_result.cookies.items():
                story.append(Paragraph(f"{key}: {value}", getSampleStyleSheet()['Normal']))

            # Display Headers
            story.append(Paragraph("Headers:", getSampleStyleSheet()['Heading4']))
            for key, value in whaweb_result.headers.items():
                story.append(Paragraph(f"{key}: {value}", getSampleStyleSheet()['Normal']))


        # Add Crtsh Results
        story.append(Paragraph("Crtsh Results:", getSampleStyleSheet()['Heading1']))
        crtsh_data = []
        for crtsh_result in crtsh_results:
            crtsh_section = [
                [crtsh_result.common_name, crtsh_result.issuer_organization, str(crtsh_result.not_before), str(crtsh_result.not_after)]
            ]
            crtsh_data.extend(crtsh_section)
        

        crtsh_table = Table(crtsh_data, colWidths=[125, 100, 125, 125], hAlign='LEFT')
        crtsh_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0c7300')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), font_size),  # Apply font size to the header row
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), '#FFFFFF'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), font_size),  # Apply font size to the data rows
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, '#000000'),
            ('WORDWRAP', (0, 1), (-1, -1), True),
        ]))

        story.append(crtsh_table)


        ###SUBDOMAIN SECTION
        story.append(Paragraph("Subdomain Scan Results:", getSampleStyleSheet()['Heading1']))
        for subdomain_result in subdomain_scan_results:
            subdomain_section = [
                Paragraph("Subdomain:", getSampleStyleSheet()['Heading4']),
                Paragraph(subdomain_result.subdomain, getSampleStyleSheet()['Normal']),
                Paragraph("Headers:", getSampleStyleSheet()['Heading4']),
            ]

            # Convert headers dictionary into a list of tuples for table data
            headers_data = list(subdomain_result.headers.items())

            if headers_data:
                headers_table_data = [
                    ['Header Name', 'Header Value']
                ] + headers_data

                # Create a table for headers
                headers_table = Table(headers_table_data, colWidths=[200, 250], hAlign='LEFT')
                headers_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0c7300')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTSIZE', (0, 0), (-1, 0), font_size),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), font_size),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ]))

                subdomain_section.append(headers_table)
            else:
                subdomain_section.append(Paragraph("No headers available.", getSampleStyleSheet()['Normal']))

            # ... Other sections ...

            # Display screenshot (if available)
            if subdomain_result.screenshot:
                screenshot_path = subdomain_result.screenshot.path
                screenshot_img = Image(screenshot_path, width=400, height=300)  # Adjust width and height as needed
                subdomain_section.append(Paragraph("Screenshot:", getSampleStyleSheet()['Heading4']))
                subdomain_section.append(screenshot_img)

            subdomain_section.extend([
                Paragraph("Nmap Results:", getSampleStyleSheet()['Heading4']),
                Paragraph(str(subdomain_result.nmap_results), getSampleStyleSheet()['Normal'])
            ])

            story.extend(subdomain_section)   # Add the elements directly to the story



        # Build the PDF document
        doc.build(story)
        return response

    except Exception as e:
        pass


##########################################################################################
class TargetInfo(View):
    def get(self, request, *args, **kwargs):
        try:
            target_id = self.kwargs.get('target_id')
            target = Target.objects.get(pk=target_id)
            directory_results = DirectoryListingResult.objects.filter(target=target)
            dns_results = DNSEnumerationResult.objects.filter(target=target)
            whaweb_results = WhawebResult.objects.filter(target=target)
            crtsh_results = CrtshResult.objects.filter(target=target)
            subdomain_results = SubdomainScanResult.objects.filter(target=target)
            crawler_results = CrawlerResult.objects.filter(target=target).first()

            context = {
                'target': target,
                'directory_results': directory_results,
                'dns_results': dns_results,
                'whaweb_results': whaweb_results,
                'crtsh_results': crtsh_results,
                'subdomain_results': subdomain_results,
                'crawler_results': crawler_results,
            }

            return render(request, 'Main/target_details.html', context)
        except Target.DoesNotExist:
            return render(request, 'target_not_found.html')




class SubdomainInfo(View):
    def get(self,request,*args,**kwargs):
        try:
            subdomain_id = self.kwargs.get('subdomain_id')
            subdomain_instance = CrtshResult.objects.get(pk=subdomain_id)
            subdomain = SubdomainScanResult.objects.get(subdomain = subdomain_instance.common_name)
            context = {
                'subdomain' : subdomain,
            }

            return render(request, 'Main/subdomain_details.html', context)
        except SubdomainScanResult.DoesNotExist:
            return render(request, 'All/404.html')



class XssSacan(View):
    def get(self,request,*args,**kwargs):
        target_url = request.session['url']
        target = get_object_or_404(Target, url=target_url)
        crawler_result = CrawlerResult.objects.filter(target=target).first()
        context = {
            'target_url' : target_url,
            'crawler_result' : crawler_result,
        }
        return render(request, 'Main/xssscan.html',context)