from .models import *
from asgiref.sync import sync_to_async
import asyncio
import aiohttp
from urllib.parse import urljoin
from channels.generic.websocket import AsyncWebsocketConsumer
import json
import dns.resolver
import requests
from bs4 import BeautifulSoup
import re
import datetime
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from django.conf import settings
import nmap
import bs4
import tldextract
import threading
##############################################DIR LISTING##################################
class DirectoryListingConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for performing directory listing using WebSocket communication.

    This consumer performs directory listing on a given URL using WebSocket communication.
    It reads directory names from a wordlist file, sends requests to the URLs formed by
    joining the base URL with each directory name, and sends updates about found directories
    to the connected WebSocket client in real-time.

    Attributes:
        stop_requested (bool): Flag indicating whether a stop request has been received.

    Methods:
        connect: Connects the WebSocket consumer.
        disconnect: Disconnects the WebSocket consumer.
        receive: Receives data from the WebSocket client and starts directory listing.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_requested = False

    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):

        """
        Receives data from the WebSocket client and starts directory listing.

        Args:
            text_data (str): JSON data received from the WebSocket client.

        JSON Data Format:
        {
            "url": "https://example.com/",
            "recursive": true,
            "extensions": [".php", ".asp"],
            "status_codes": [200, 403],
            "timeout": 5
        }

        Notes:
            - The "recursive" flag indicates whether to perform recursive directory listing.
            - The "extensions" list specifies allowed file extensions (optional).
            - The "status_codes" list specifies allowed HTTP status codes (optional).
            - The "timeout" specifies the request timeout (optional).

        Example JSON Data:
        {
            "url": "https://example.com/",
            "recursive": true,
            "extensions": [".php", ".asp"],
            "status_codes": [200, 403],
            "timeout": 5
        }
        """
        data = json.loads(text_data)
        ###############################
        if 'stop' in data and data['stop'] == True:
            self.stop_requested = True
            return

        url =self.scope["session"].get('url')
        recursive = data.get('recursive', False)
        extensions = data.get('extensions')
        status_codes = data.get('status_codes', [200])
        timeout = data.get('timeout', 5)
        wordlist = 'constants/dir.txt'

        # this is used to stored already visited URLS
        visited_urls = set()

        await self.dirbuser(url, wordlist, recursive, extensions, status_codes, visited_urls, timeout)

    async def fetch_url(self, session, url, timeout):
        try:
            async with session.get(url, timeout=timeout) as response:
                return response.status, await response.text()
        except asyncio.TimeoutError:
            print(f"Timeout connecting to {url}")
        except aiohttp.ClientError as e:
            print(f"Error connecting to {url}: {str(e)}")
        return None, None

    async def dirbuser(self, url, wordlist, recursive=False, extensions=None, status_codes=None, visited_urls=None, timeout=5):
        if visited_urls is None:
            visited_urls = set()

        async with aiohttp.ClientSession() as session:
            try:
                with open(wordlist, 'r') as file:
                    for line in file:
                        if self.stop_requested:
                            break

                        word = line.strip()
                        dir_url = urljoin(url, word)
                        try:
                            if dir_url in visited_urls:
                                continue

                            visited_urls.add(dir_url)
                            status_code, response_text = await self.fetch_url(session, dir_url, timeout)

                            if status_code is not None and status_code in status_codes:
                                if extensions is None or any(dir_url.endswith(ext) for ext in extensions):
                                    print(f"[FOUND] {dir_url}")

                                    #################Save The Results To The Database###############
                                    if DirectoryListingResult.objects.filter(target=url):
                                        pass
                                    else:
                                        result = DirectoryListingResult(target=url, directory=dir_url)
                                        result.save()

                                    await self.send(text_data=json.dumps({'directory': dir_url}))

                            if recursive and status_code == 200 and response_text is not None:
                                await self.dirbuser(dir_url, wordlist, recursive, extensions, status_codes, visited_urls, timeout)

                        except KeyboardInterrupt:
                            print("\nProgram interrupted by user.")
                            break

            except FileNotFoundError:
                print(f"Wordlist file not found: {wordlist}")
            except IOError:
                print(f"Error reading wordlist file: {wordlist}")
            finally:
                # Send a message to indicate that the directory listing is complete
                await self.send(text_data=json.dumps({'directory': 'Listing completed.'}))


##############################################DNS ENUMERATION SECTION###################
class DNSEnumerationConsumer(AsyncWebsocketConsumer):
    """
    this is a consumer for performing DNS enumeration using WebSocket communication.

    This consumer performs DNS enumeration on a given domain using WebSocket communication.
    It performs DNS queries for various record types and sends the results back to the
    connected WebSocket client in real-time. The DNS enumeration results are also saved
    in the database.

    Attributes:
        record_types (list): List of DNS record types to query.
        client_connected (bool): Flag indicating whether a client is connected.

    Methods:
        connect: Connects the WebSocket consumer.
        disconnect: Disconnects the WebSocket consumer and stops enumeration.
        receive: Receives data from the WebSocket client and performs DNS enumeration.

    Usage:
        To use this consumer, create a WebSocket route that maps to the
        DNSEnumerationConsumer class. The consumer expects JSON data containing the target
        domain. It performs DNS enumeration for various record types and sends the results
        back to the connected client.
    """
    record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_connected = True

    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        self.client_connected = False
        pass

    async def receive(self, text_data):
        url = self.scope["session"].get('url')
        data = json.loads(text_data)

        if not url:
            await self.send(text_data=json.dumps({'error': 'Invalid request: target_domain is missing'}))
            return

        results = await self.perform_dns_enumeration(url)

        # Send the DNS enumeration results back to the client
        await self.send(text_data=json.dumps(results))

    async def perform_dns_enumeration(self, url):
        results = {}
        if not self.client_connected:
            return
        if url.startswith("https://"):
            domain = url[8:]
        elif url.startswith("http://"):
            domain = url[7:]
        else :
            return

        try:
            for record_type in DNSEnumerationConsumer.record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    record_list = []
                    for answer in answers:
                        record_list.append(answer.to_text())

                    results[record_type] = record_list

                    # Save results in the database
                    target_instance = await sync_to_async(Target.objects.get)(url=url)
                    if not await sync_to_async(DNSEnumerationResult.objects.filter(target=target_instance, record_type=record_type).exists)():
                        result = DNSEnumerationResult(
                            target=target_instance,
                            record_type=record_type,
                            records=record_list
                        )
                        await sync_to_async(result.save)()
                    else : 
                        print("ALREADY EXISTS")

                except dns.resolver.NoAnswer:
                    pass

                except dns.resolver.NXDOMAIN:
                    print(f'{domain} does not exist')

                except dns.resolver.Timeout:
                    print(f'Timeout occurred while resolving {record_type} records for {domain}')

        except dns.resolver.NoNameservers:
            print(f'No nameservers found for {domain}')

        return results



####################################################WHATWEB###################################
class WhatWebConsumer(AsyncWebsocketConsumer):
    """
    A consumer for performing web fingerprinting using the WhatWeb tool.

    This consumer connects to a WebSocket and processes URL data sent from the client.
    It uses the WhatWeb tool to gather information about the provided URL, such as server,
    technology, title, meta tags, cookies, and headers. The gathered data is then sent back
    to the client through the WebSocket.

    Attributes:
        None

    Methods:
        connect: Establishes a WebSocket connection.
        disconnect: Closes the WebSocket connection.
        receive: Receives and processes URL data from the client.

    Usage:
        To use this consumer, connect to the WebSocket endpoint and send a JSON payload
        containing the 'url' parameter. The consumer will perform web fingerprinting using
        the WhatWeb tool and send the results back to the client.

    Example:
        Payload sent by the client:
        {
            "url": "https://example.com"
        }
        
        Expected response from the consumer:
        {
            "url": "https://example.com",
            "server": "nginx",
            "technology": "PHP/7.4.3",
            "title": "Example Domain",
            "meta_tags": {
                "description": "This is an example domain",
                "keywords": "example, domain",
                ...
            },
            "cookies": {
                "session": "12345",
                ...
            },
            "headers": {
                "Date": "Sun, 07 Aug 2023 12:34:56 GMT",
                ...
            }
        }
    """
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        url = self.scope["session"].get('url')
        if url:
            await self.process_url(url)
        else:
            await self.send(text_data=json.dumps({'error': 'Invalid request: URL is missing'}))

    async def process_url(self, url):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                headers = response.headers

                server = headers.get('Server', '')
                technology = headers.get('X-Powered-By', '')

                soup = BeautifulSoup(response.content, 'html.parser')
                title = soup.title.string if soup.title else ''

                meta_tags = {}
                for meta_tag in soup.find_all('meta'):
                    name = meta_tag.get('name', '')
                    content = meta_tag.get('content', '')
                    if name and content:
                        meta_tags[name] = content

                cookies = {}
                for cookie in response.cookies:
                    cookies[cookie.name] = cookie.value

                result = {
                    'url': url,
                    'server': server,
                    'technology': technology,
                    'title': title,
                    'meta_tags': meta_tags,
                    'cookies': cookies,
                    'headers': dict(headers)
                }
                ##########SAVE THE RESULTS TO THE DATABASE########################
                target_instance = await sync_to_async(Target.objects.get)(url=url)
                if not await sync_to_async(WhawebResult.objects.filter(target=target_instance).exists)():
                    whatweb_result = WhawebResult(
                        target=target_instance,
                        server=server,
                        technology=technology,
                        title=title,
                        meta_tags=meta_tags,
                        cookies=cookies,
                        headers=dict(headers),
                    )
                    await sync_to_async(whatweb_result.save)()
                else : 
                    print("ALREADY EXISTS")

                ###################################################################
                json_data = json.dumps(result, indent=4)
                await self.send(text_data=json_data)
            else:
                await self.send(text_data=json.dumps({'error': f"Received HTTP status code {response.status_code}"}))
        except requests.exceptions.RequestException as e:
            await self.send(text_data=json.dumps({'error': str(e)}))



########################################crtsh#######################################################
class CRTSHConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        url = self.scope["session"].get('url')
        

        if url:
            await self.search_crtsh(url)
        else:
            await self.send(text_data=json.dumps({"error": "Domain name is required."}))

    async def search_crtsh(self, url):
        if url.startswith("https://"):
            domain = url[8:]
        elif url.startswith("http://"):
            domain = url[7:]
        else :
            return
        base_url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(base_url)
        if not response.ok:
            await self.send(text_data=json.dumps({"error": "Error retrieving crt.sh data."}))
            return

        certificates = response.json()
        certificate_data = []
        processed_common_names = set()

        for cert in certificates:
            common_name = cert.get("common_name", "")
            issuer_name = cert.get("issuer_name", "")
            not_before = cert.get("not_before", "")
            not_after = cert.get("not_after", "")
            extensions = cert.get("extensions", "")

            if not common_name or not issuer_name or not not_before or not not_after:
                continue

            if common_name in processed_common_names:
                continue  

            not_before_date = datetime.datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%S")
            not_after_date = datetime.datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")

            issuer_organization = re.search(r"O=([\w\s]+)", issuer_name)
            issuer_organization = issuer_organization.group(1) if issuer_organization else ""

            matching_identities = []
            if extensions:
                for extension in extensions:
                    if "key" in extension and extension["key"] == "2.5.29.17":
                        matching_identities = extension.get("value", "").split(",")

            ##########SAVE THE RESULTS TO THE DATABASE########################
            target_instance = await sync_to_async(Target.objects.get)(url=url)
            if not await sync_to_async(CrtshResult.objects.filter(common_name=common_name).exists)():
                crtsh_result = CrtshResult(
                    target=target_instance,
                    common_name=common_name,
                    issuer_organization=issuer_organization,
                    not_before=not_before,
                    not_after=not_after,
                )
                await sync_to_async(crtsh_result.save)()
            else : 
                print("ALREADY EXISTS")

            ###################################################################
            certificate_info = {
                "Common Name": common_name,
                "Issuer Organization": issuer_organization,
                "Not Before": not_before_date.strftime("%Y-%m-%d %H:%M:%S"),
                "Not After": not_after_date.strftime("%Y-%m-%d %H:%M:%S"),
                "Matching Identities": matching_identities,
            }

            certificate_data.append(certificate_info)
            processed_common_names.add(common_name)

        if certificate_data:
            await self.send(text_data=json.dumps(certificate_data))
        else:
            await self.send(text_data=json.dumps({"error": "No certificate data found for the domain."}))


########################################Subdomain Scannig#######################################
class SubdomainScanConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            url = self.scope["session"].get('url')
            subdomain_id = data.get("subdomain_id")
            if url.startswith("https://"):
                subdomain = url[8:]
            elif url.startswith("http://"):
                subdomain = url[7:]
            else :
                return
            subdomain_instance = await sync_to_async(CrtshResult.objects.get)(id=subdomain_id)

            if subdomain_instance:
                headers = await self.get_headers(subdomain_instance.common_name)
                screenshot_path = await self.take_screenshot(subdomain_instance.common_name)
                nmap_results = await self.run_nmap_scan(subdomain_instance.common_name)

                if isinstance(screenshot_path, dict) and "error" in screenshot_path:
                    screenshot_path = None

                headers_dict = dict(headers)

                response_data = {
                    "headers": headers_dict,
                    "screenshot": screenshot_path,
                    "nmap_results": nmap_results,
                }

                ##########SAVE THE RESULTS TO THE DATABASE########################
                target_instance = await sync_to_async(Target.objects.get)(pk=subdomain_instance.target_id)
                if not await sync_to_async(SubdomainScanResult.objects.filter(subdomain=subdomain_instance.common_name).exists)():
                    subdomainscan_result = SubdomainScanResult(
                        target=target_instance,
                        subdomain=subdomain_instance.common_name,
                        headers=headers_dict,
                        screenshot=screenshot_path,
                        nmap_results=dict(nmap_results),
                    )
                    await sync_to_async(subdomainscan_result.save)()
                else: 
                    print("ALREADY EXISTS")
                ###################################################################
                await self.send(text_data=json.dumps(response_data))
            else:
                await self.send(text_data=json.dumps({"error": "Subdomain is required."}))
        except Exception as e:
            await self.send(text_data=json.dumps({"error": str(e)}))

    async def get_headers(self, subdomain):
        url = f"http://{subdomain}"
        try:
            response = requests.head(url, timeout=10)
            return response.headers
        except requests.RequestException as e:
            return {"error": str(e)}

    async def take_screenshot(self, subdomain):
        firefox_options = FirefoxOptions()
        firefox_options.headless = True
        firefox_driver = "/usr/local/bin/geckodriver-master"  # Adjust the path to your geckodriver executable
        driver = webdriver.Firefox(options=firefox_options)  # Use executable_path

        try:
            url = f"http://{subdomain}"
            driver.get(url)
            screenshot_path = os.path.join(settings.MEDIA_ROOT, f"{subdomain}.png")
            driver.save_screenshot(screenshot_path)
            return f"{subdomain}.png"
        except Exception as e:
            return {"error": str(e)}
        finally:
            driver.quit()

    async def run_nmap_scan(self, subdomain):
        nm = nmap.PortScanner()
        target_host = f"{subdomain}"
        try:
            nm.scan(hosts=target_host, arguments="-T4 -F")
            if target_host in nm.all_hosts():
                return nm[target_host].all_tcp()
            else:
                return {"error": "Target host not found in Nmap scan results."}
        except nmap.PortScannerError as e:
            return {"error": str(e)}


##################################CRAWLER###########################
requests.packages.urllib3.disable_warnings()
user_agent = {'User-Agent': 'Pavaste'}
class CrawlerConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_connected = True
        self.r_total=[]
        self.sm_total=[]
        self.css_total = []
        self.js_total = []
        self.int_total = []
        self.ext_total = []
        self.img_total = []
        self.js_crawl_total = []
        self.sm_crawl_total = []
        self.sm_url = ''

    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        target_url = self.scope["session"].get('url')
        if target_url:
            await self.crawler(target_url)
        else:
            await self.send_error_message("Target URL not provided.")

    async def send_error_message(self, error_message):
        response_data = {
            'error': str(error_message)  # Convert to string to make it JSON serializable
        }
        await self.send(text_data=json.dumps(response_data))

    async def send_crawler_results(self, results):
        await self.send(text_data=json.dumps(results))

    async def crawler(self, target):
        response_data = {
            'status': 'success',
            'results': {}
        }

        try:
            rqst = requests.get(target, headers=user_agent, verify=False, timeout=10)
        except Exception as e:
            error_message = f'Exception: {e}'
            await self.send_error_message(error_message)
            return

        sc = rqst.status_code
        if sc == 200:
            page = rqst.content
            soup = bs4.BeautifulSoup(page, 'lxml')

            protocol = target.split('://')
            protocol = protocol[0]
            temp_tgt = target.split('://')[1]
            pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}'
            custom = bool(re.match(pattern, temp_tgt))
            if custom is True:
                r_url = f'{protocol}://{temp_tgt}/robots.txt'
                self.sm_url = f'{protocol}://{temp_tgt}/sitemap.xml'
                base_url = f'{protocol}://{temp_tgt}'
            else:
                ext = tldextract.extract(target)
                hostname = '.'.join(part for part in ext if part)
                base_url = f'{protocol}://{hostname}'
                r_url = f'{base_url}/robots.txt'
                self.sm_url = f'{base_url}/sitemap.xml'

            response_data['results']['robots'] = await self.robots(r_url,base_url)
            response_data['results']['sitemap'] = await self.sitemap(self.sm_url)
            response_data['results']['css'] = await self.css(soup,target)
            response_data['results']['js'] = await self.js(soup,target)
            response_data['results']['internal_links'] = await self.internal_links(soup,target)
            response_data['results']['external_links'] = await self.external_links(soup,target)
            response_data['results']['images'] = await self.images(soup,target)
            response_data['results']['sm_total']=await self.sm_crawl()
            response_data['results']['js_total']=await self.js_crawl()

            ##########SAVE THE RESULTS TO THE DATABASE########################
            target_instance = await sync_to_async(Target.objects.get)(url=target)
            if not await sync_to_async(CrawlerResult.objects.filter(target=target_instance).exists)():
                crawler_result = CrawlerResult(
                    target=target_instance,
                    robots_results=response_data['results']['robots'],
                    sitemap_results=response_data['results']['sitemap'],
                    css_results=response_data['results']['css'],
                    js_results=response_data['results']['js'],
                    internal_links=response_data['results']['internal_links'],
                    external_links=response_data['results']['external_links'],
                    image_links=response_data['results']['images'],
                    crawled_sitemap_links=response_data['results']['sm_total'],
                    crawled_js_links=response_data['results']['js_total'],
                )
                await sync_to_async(crawler_result.save)()
            else : 
                print("ALREADY EXISTS")

            await self.send_crawler_results(response_data)
        else:
            error_message = f'Status Code: {sc}'
            await self.send_error_message(error_message)


    def url_filter(self,target,link):
        if all([link.startswith('/') is True, link.startswith('//') is False]):
            ret_url = target + link
            return ret_url
        else:
            pass

        if link.startswith('//') is True:
            ret_url = link.replace('//', 'http://')
            return ret_url
        else:
            pass

        if all([
            link.find('//') == -1,
            link.find('../') == -1,
            link.find('./') == -1,
            link.find('http://') == -1,
            link.find('https://') == -1]
        ):
            ret_url = f'{target}/{link}'
            return ret_url
        else:
            pass

        if all([
            link.find('http://') == -1,
            link.find('https://') == -1]
        ):
            ret_url = link.replace('//', 'http://')
            ret_url = link.replace('../', f'{target}/')
            ret_url = link.replace('./', f'{target}/')
            return ret_url
        else:
            pass
        return link



    async def robots(self,r_url, base_url):
        try:
            r_rqst = requests.get(r_url, headers=user_agent, verify=False, timeout=10)
            r_sc = r_rqst.status_code
            if r_sc == 200:
                r_page = r_rqst.text
                r_scrape = r_page.split('\n')
                for entry in r_scrape:
                    if any([
                        entry.find('Disallow') == 0,
                        entry.find('Allow') == 0,
                        entry.find('Sitemap') == 0]):
                        url = entry.split(': ')
                        try:
                            url = url[1]
                            url = url.strip()
                            tmp_url = self.url_filter(base_url, url)
                            if tmp_url is not None:
                                self.r_total.append(self.url_filter(base_url, url))
                            if url.endswith('xml') is True:
                                self.sm_total.append(url)
                        except Exception as e:
                            print(str(e))
                if self.r_total:
                    return list(self.r_total) # Convert set to list before returning

                else : 
                    return list()

            elif r_sc == 404:
                return list()
                
            else:
                return list("Error fetching robots.txt")
        except Exception as e:
            return str(e)  # Convert the exception to a string

    async def sitemap(self , sm_url):
        try:
            sm_rqst = requests.get(sm_url, headers=user_agent, verify=False, timeout=10)
            sm_sc = sm_rqst.status_code
            if sm_sc == 200:
                sm_page = sm_rqst.content
                sm_soup = bs4.BeautifulSoup(sm_page, 'xml')
                links = sm_soup.find_all('loc')
                for url in links:
                    url = url.get_text()
                    if url is not None:
                        self.sm_total.append(url)

                if self.sm_total:
                    return list(self.sm_total)

                else : 
                    return list()

            elif sm_sc == 404:
                return list()
            else:
                return list("Error fetching sitemaps")
        except Exception as e:
            await self.send_error_message(str(e))

    async def css(self,soup,target):
        css = soup.find_all('link', href=True)

        for link in css:
            url = link.get('href')
            if url is not None and '.css' in url:
                self.css_total.append(self.url_filter(target, url))

        return list(self.css_total)

    async def js(self,soup,target):
        scr_tags = soup.find_all('script', src=True)

        for link in scr_tags:
            url = link.get('src')
            if url is not None and '.js' in url:
                tmp_url = self.url_filter(target, url)
                if tmp_url is not None:
                    self.js_total.append(tmp_url)

        return list(self.js_total)

    async def internal_links(self,soup,target):
        ext = tldextract.extract(target)
        domain = ext.registered_domain

        links = soup.find_all('a')
        for link in links:
            url = link.get('href')
            if url is not None:
                if domain in url:
                    self.int_total.append(url)

        return list(self.int_total)

    async def external_links(self,soup,target):
        ext = tldextract.extract(target)
        domain = ext.registered_domain

        links = soup.find_all('a')
        for link in links:
            url = link.get('href')
            if url is not None:
                if domain not in url and 'http' in url:
                    self.ext_total.append(url)

        return list(self.ext_total)

    async def images(self,soup,target):
        image_tags = soup.find_all('img')

        for link in image_tags:
            url = link.get('src')
            if url is not None and len(url) > 1:
                self.img_total.append(self.url_filter(target, url))

        return list(self.img_total)
    
    async def sm_crawl(self):
        threads = []

        def fetch(site_url):
            try:
                sm_rqst = requests.get(site_url, headers=user_agent, verify=False, timeout=10)
                sm_sc = sm_rqst.status_code
                if sm_sc == 200:
                    sm_data = sm_rqst.content.decode()
                    sm_soup = bs4.BeautifulSoup(sm_data, 'xml')
                    links = sm_soup.find_all('loc')
                    for url in links:
                        url = url.get_text()
                        if url is not None:
                            self.sm_crawl_total.append(url)
                elif sm_sc == 404:
                    pass
                else:
                    pass
            except Exception:
                pass

        for site_url in self.sm_total:
            if site_url != self.sm_url:
                if site_url.endswith('xml') is True:
                    t = threading.Thread(target=fetch, args=[site_url])
                    t.daemon = True
                    threads.append(t)
                    t.start()

        for thread in threads:
            thread.join()
        return list(self.sm_crawl_total)
    


    async def js_crawl(self):
        threads = []

        def fetch(js_url):
            try:
                js_rqst = requests.get(js_url, headers=user_agent, verify=False, timeout=10)
                js_sc = js_rqst.status_code
                if js_sc == 200:
                    js_data = js_rqst.content.decode()
                    js_data = js_data.split(';')
                    for line in js_data:
                        if any(['http://' in line, 'https://' in line]):
                            found = re.findall(r'\"(http[s]?://.*?)\"', line)
                            for item in found:
                                if len(item) > 8:
                                    self.js_crawl_total.append(item)
            except Exception as e:
                pass

        for js_url in self.js_total:
            t = threading.Thread(target=fetch, args=[js_url])
            t.daemon = True
            threads.append(t)
            t.start()

        for thread in threads:
            thread.join()
        
        return list(self.js_crawl_total)


############################################
# import socket
# import asyncio
# from datetime import date
# from channels.generic.websocket import AsyncWebsocketConsumer
# import aiohttp

# R = '\033[31m'  # red
# G = '\033[32m'  # green
# C = '\033[36m'  # cyan
# W = '\033[0m'   # white
# Y = '\033[33m'  # yellow

# header = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0'}
# curr_yr = date.today().year
# last_yr = curr_yr - 1

# class DirectoryEnumConsumer(AsyncWebsocketConsumer):
#     async def connect(self):
#         await self.accept()

#     async def disconnect(self, close_code):
#         pass

#     async def receive(self, text_data):
#         data = json.loads(text_data)
#         target = data['target']
#         threads = data['threads']
#         tout = data['timeout']
#         wdlist = data['wordlist']
#         redir = data['allow_redirects']
#         sslv = data['ssl_verification']
#         dserv = data['dns_servers']
#         output = data['output']
#         filext = data['file_extensions']

#         await self.process_directory_enum(target, threads, tout, wdlist, redir, sslv, dserv, output, filext)

#     async def process_directory_enum(self, target, threads, tout, wdlist, redir, sslv, dserv, output, filext):
#         queue = asyncio.Queue()

#         resolver = aiohttp.AsyncResolver(nameservers=dserv.split(', '))
#         conn = aiohttp.TCPConnector(limit=threads, resolver=resolver, family=socket.AF_INET, verify_ssl=sslv)
#         timeout = aiohttp.ClientTimeout(total=None, sock_connect=tout, sock_read=tout)

#         async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
#             distrib = asyncio.create_task(self.insert(queue, filext, target, wdlist, redir))
#             workers = [
#                 asyncio.create_task(self.consumer(queue, target, session, redir))
#                 for _ in range(threads)
#             ]

#             await asyncio.gather(distrib)
#             await queue.join()

#             for worker in workers:
#                 worker.cancel()

#         self.dir_output(output)

#     async def fetch(self, url, session, redir):
#         try:
#             async with session.get(url, headers=header, allow_redirects=redir) as response:
#                 return response.status
#         except Exception as e:
#             print(f'{R}[-] {C}Exception : {W}' + str(e).strip('\n'))

#     async def insert(self, queue, filext, target, wdlist, redir):
#         if len(filext) == 0:
#             url = target + '/{}'
#             with open(wdlist, 'r') as wordlist:
#                 for word in wordlist:
#                     word = word.strip()
#                     await queue.put([url.format(word), redir])
#                     await asyncio.sleep(0)
#         else:
#             filext = ',' + filext
#             filext = filext.split(',')
#             with open(wdlist, 'r') as wordlist:
#                 for word in wordlist:
#                     for ext in filext:
#                         ext = ext.strip()
#                         if len(ext) == 0:
#                             url = target + '/{}'
#                         else:
#                             url = target + '/{}.' + ext
#                         word = word.strip()
#                         await queue.put([url.format(word), redir])
#                         await asyncio.sleep(0)

#     async def consumer(self, queue, target, session, redir):
#         while True:
#             values = await queue.get()
#             url = values[0]
#             redir = values[1]
#             status = await self.fetch(url, session, redir)
#             await self.filter_out(target, url, status)
#             queue.task_done()

#     async def filter_out(self, target, url, status):
#         if status in {200}:
#             if str(url) != target + '/':
#                 await self.send(f'{G}{status} {C}|{W} {url}')
#         elif status in {301, 302, 303, 307, 308}:
#             await self.send(f'{Y}{status} {C}|{W} {url}')
#         elif status in {403}:
#             await self.send(f'{R}{status} {C}|{W} {url}')

#     async def dir_output(self, output):
#         # Implement the dir_output function logic here
#         pass
################################################