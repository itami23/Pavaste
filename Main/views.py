from django.shortcuts import render,redirect
from django.http import HttpResponse
import json
from .forms import *

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

    


###############################
def main(request):
    if request.method == 'POST':
        form = URLForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            # Store the URL in the session so it can be accessed later
            request.session['url'] = url
            return redirect('index')  # Redirect to the new page
    else:
        form = URLForm()

    return render(request, 'Main/main.html', {'form': form})
####################################


