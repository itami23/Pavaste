from django.shortcuts import render
from django.http import HttpResponse
import json

def index(request):
    return render(request, 'Main/index.html')


def dns_enumeration(request):
    return render(request, 'Main/dnsenum.html')

def whatweb_tool_view(request):
    return render(request, 'Main/whatweb_tool.html')

    