############################################################THIS IS ITTTTTTTTTTTTTTTTTTTTTTTTTTT###########################################################


# consumers.py
# import asyncio
# import aiohttp
# import requests
# from urllib.parse import urljoin
# from channels.generic.websocket import AsyncWebsocketConsumer
# import json

# class DirectoryListingConsumer(AsyncWebsocketConsumer):
#     async def connect(self):
#         await self.accept()

#     async def disconnect(self, close_code):
#         pass

#     async def receive(self, text_data):
#         # Parse the input data sent from the client (website URL and other options)
#         data = json.loads(text_data)
#         url = data['url']
#         recursive = data.get('recursive', False)
#         extensions = data.get('extensions')
#         status_codes = data.get('status_codes', [200])
#         timeout = data.get('timeout', 5)
#         wordlist = '/home/itami/Desktop/Projects/PavasteScripts/scripts/dir.txt'

#         # Create a set to store the visited URLs to avoid duplicates
#         visited_urls = set()

#         await self.dirbuser(url, wordlist, recursive, extensions, status_codes, visited_urls, timeout)

#     async def dirbuser(self, url, wordlist, recursive=False, extensions=None, status_codes=None, visited_urls=None, timeout=5):
#         if visited_urls is None:
#             visited_urls = set()

#         try:
#             with open(wordlist, 'r') as file:
#                 for line in file:
#                     if self.scope.get('stop_requested'):
#                         # Stop directory listing if stop_requested is True
#                         break

#                     word = line.strip()
#                     dir_url = urljoin(url, word)
#                     try:
#                         if dir_url in visited_urls:
#                             continue

#                         visited_urls.add(dir_url)
#                         response = requests.get(dir_url, timeout=timeout)
                        
#                         #print(f'{status_codes} ----- {response.status_code}------{dir_url}')
#                         if response.status_code in status_codes:
#                             if extensions is None or any(dir_url.endswith(ext) for ext in extensions):
#                                 print(f"[FOUND] {dir_url}")
#                                 await self.send(text_data=json.dumps({'directory': dir_url}))
                        

#                         if recursive and response.status_code == 200 and response.headers.get('Content-Type', '').startswith('text/html'):
#                             await self.dirbuser(dir_url, wordlist, recursive, extensions, status_codes, visited_urls, timeout)

#                         # Sleep to demonstrate real-time updates (you can remove this in production)
#                         #await asyncio.sleep(1)

#                     except requests.exceptions.RequestException as e:
#                         print(f"Error connecting to {dir_url}: {str(e)}")
#                     except requests.exceptions.Timeout:
#                         print(f"Timeout connecting to {dir_url}")
#                     except KeyboardInterrupt:
#                         print("\nProgram interrupted by user.")
#                         break

#         except FileNotFoundError:
#             print(f"Wordlist file not found: {wordlist}")
#         except IOError:
#             print(f"Error reading wordlist file: {wordlist}")
#         finally:
#             # Send a message to indicate that the directory listing is complete
#             await self.send(text_data=json.dumps({'directory': 'Listing completed.'}))






##############################################DIR LISTING###################################################################################################################




import asyncio
import aiohttp
from urllib.parse import urljoin
from channels.generic.websocket import AsyncWebsocketConsumer
import json

class DirectoryListingConsumer(AsyncWebsocketConsumer):

    ####################################

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_requested = False

    ####################################

    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        # Parse the input data sent from the client (website URL and other options)
        data = json.loads(text_data)
        ###############################
        if 'stop' in data and data['stop'] == True:
            self.stop_requested = True
            return
        ################################
        url = data['url']
        recursive = data.get('recursive', False)
        extensions = data.get('extensions')
        status_codes = data.get('status_codes', [200])
        timeout = data.get('timeout', 5)
        wordlist = '/home/itami/Desktop/Projects/PavasteScripts/scripts/dir.txt'

        # Create a set to store the visited URLs to avoid duplicates
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
                        ###########
                        if self.stop_requested:
                            break
                        ###########

                        word = line.strip()
                        dir_url = urljoin(url, word)
                        try:
                            if dir_url in visited_urls:
                                continue

                            visited_urls.add(dir_url)

                            # Use async HTTP request with aiohttp
                            status_code, response_text = await self.fetch_url(session, dir_url, timeout)

                            if status_code is not None and status_code in status_codes:
                                if extensions is None or any(dir_url.endswith(ext) for ext in extensions):
                                    print(f"[FOUND] {dir_url}")
                                    await self.send(text_data=json.dumps({'directory': dir_url}))

                            if recursive and status_code == 200 and response_text is not None:
                                await self.dirbuser(dir_url, wordlist, recursive, extensions, status_codes, visited_urls, timeout)

                            # Sleep to demonstrate real-time updates (you can remove this in production)
                            # await asyncio.sleep(1)

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





###########################################################################DNS ENUMERATION SECTION########################################################
# dns_enumeration/consumers.py

import dns.resolver
import json
import asyncio

class DNSEnumerationConsumer(AsyncWebsocketConsumer):
    record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']

    ################################################

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_connected = True

    ###############################################

    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        ##############################
        self.client_connected = False
        ##############################
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        target_domain = data.get('target_domain')

        if not target_domain:
            await self.send(text_data=json.dumps({'error': 'Invalid request: target_domain is missing'}))
            return

        results = await self.perform_dns_enumeration(target_domain)

        # Send the DNS enumeration results back to the client
        await self.send(text_data=json.dumps(results))

    async def perform_dns_enumeration(self, domain):
        results = {}

        #########################################
        if not self.client_connected:
            print("Consumer Stoped")
            return
        #########################################

        try:
            for record_type in DNSEnumerationConsumer.record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    record_list = []
                    for answer in answers:
                        record_list.append(answer.to_text())

                    results[record_type] = record_list

                except dns.resolver.NoAnswer:
                    pass

                except dns.resolver.NXDOMAIN:
                    print(f'{domain} does not exist')

                except dns.resolver.Timeout:
                    print(f'Timeout occurred while resolving {record_type} records for {domain}')

        except dns.resolver.NoNameservers:
            print(f'No nameservers found for {domain}')

        return results




################################################################WHATWEB###################################
# WhatWebApp/consumers.py
import json
import requests
from bs4 import BeautifulSoup
from channels.generic.websocket import AsyncWebsocketConsumer

class WhatWebConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        url = data.get('url', '')

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

                json_data = json.dumps(result, indent=4)
                await self.send(text_data=json_data)
            else:
                await self.send(text_data=json.dumps({'error': f"Received HTTP status code {response.status_code}"}))
        except requests.exceptions.RequestException as e:
            await self.send(text_data=json.dumps({'error': str(e)}))



########################################crtsh#######################################################
import requests
import re
import datetime
import json
from channels.generic.websocket import AsyncWebsocketConsumer


class CRTSHConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        domain = data.get("domain")

        if domain:
            await self.search_crtsh(domain)
        else:
            await self.send(text_data=json.dumps({"error": "Domain name is required."}))

    async def search_crtsh(self, domain):
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


##########################################Subdomain Scannig#######################################
# import os
# import json
# import requests
# from selenium import webdriver
# from selenium.webdriver.firefox.options import Options as FirefoxOptions
# from django.conf import settings
# from channels.generic.websocket import AsyncWebsocketConsumer
# import nmap

# class SubdomainScanConsumer(AsyncWebsocketConsumer):
#     async def connect(self):
#         await self.accept()

#     async def disconnect(self, close_code):
#         pass

#     async def receive(self, text_data):
#         data = json.loads(text_data)
#         subdomain = data.get("subdomain")

#         if subdomain:
#             headers = await self.get_headers(subdomain)
#             screenshot_path = await self.take_screenshot(subdomain)

#             # Convert headers to a regular dictionary
#             headers_dict = dict(headers)

#             response_data = {
#                 "headers": headers_dict,
#                 "screenshot": screenshot_path,
#             }

#             await self.send(text_data=json.dumps(response_data))
#         else:
#             await self.send(text_data=json.dumps({"error": "Subdomain is required."}))

#     async def get_headers(self, subdomain):
#         url = f"http://{subdomain}"
#         try:
#             response = requests.head(url, timeout=10)
#             return response.headers
#         except requests.RequestException as e:
#             return {"error": str(e)}

#     async def take_screenshot(self, subdomain):
#         firefox_options = FirefoxOptions()
#         firefox_options.headless = True
#         firefox_driver = "/usr/local/bin/geckodriver-master"  # Adjust the path to your geckodriver executable
#         driver = webdriver.Firefox(options=firefox_options)  # Use executable_path

#         try:
#             url = f"http://{subdomain}"
#             driver.get(url)
#             screenshot_path = os.path.join(settings.MEDIA_ROOT, f"{subdomain}.png")
#             driver.save_screenshot(screenshot_path)
#             return f"{subdomain}.png"
#         except Exception as e:
#             return {"error": str(e)}
#         finally:
#             driver.quit()


import os
import json
import requests
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from django.conf import settings
from channels.generic.websocket import AsyncWebsocketConsumer
import nmap

class SubdomainScanConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        subdomain = data.get("subdomain")

        if subdomain:
            headers = await self.get_headers(subdomain)
            screenshot_path = await self.take_screenshot(subdomain)
            nmap_results = await self.run_nmap_scan(subdomain)

            # Convert headers to a regular dictionary
            headers_dict = dict(headers)

            response_data = {
                "headers": headers_dict,
                "screenshot": screenshot_path,
                "nmap_results": nmap_results,
            }

            await self.send(text_data=json.dumps(response_data))
        else:
            await self.send(text_data=json.dumps({"error": "Subdomain is required."}))

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
import re
import bs4
import tldextract
import json
from channels.generic.websocket import AsyncWebsocketConsumer
import requests

requests.packages.urllib3.disable_warnings()

user_agent = {'User-Agent': 'FinalRecon'}

class CrawlerConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        target_url = data.get('url')
        print(target_url)

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
                sm_url = f'{protocol}://{temp_tgt}/sitemap.xml'
                base_url = f'{protocol}://{temp_tgt}'
            else:
                ext = tldextract.extract(target)
                hostname = '.'.join(part for part in ext if part)
                base_url = f'{protocol}://{hostname}'
                r_url = f'{base_url}/robots.txt'
                sm_url = f'{base_url}/sitemap.xml'

            # loop = asyncio.new_event_loop()
            # asyncio.set_event_loop(loop)

            response_data['results']['robots'] = await self.robots(r_url,base_url)
            response_data['results']['sitemap'] = await self.sitemap(sm_url)
            response_data['results']['css'] = await self.css(soup,target)
            response_data['results']['js'] = await self.js(soup,target)
            response_data['results']['internal_links'] = await self.internal_links(soup,target)
            response_data['results']['external_links'] = await self.external_links(soup,target)
            response_data['results']['images'] = await self.images(soup,target)

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
        r_total = []

        try:
            r_rqst = requests.get(r_url, headers=user_agent, verify=False, timeout=10)
            r_sc = r_rqst.status_code
            if r_sc == 200:
                print("deeez")
                r_page = r_rqst.text
                r_scrape = r_page.split('\n')
                print(r_scrape)
                for entry in r_scrape:
                    if any([
                        entry.find('Disallow') == 0,
                        entry.find('Allow') == 0,
                        entry.find('Sitemap') == 0]):
                        print(entry)
                        url = entry.split(': ')
                        try:
                            url = url[1]
                            url = url.strip()
                            tmp_url = self.url_filter(base_url, url)
                            print(f"tmp_url {tmp_url}")
                            if tmp_url is not None:
                                r_total.append(self.url_filter(base_url, url))
                            # if url.endswith('xml') is True:
                            #     sm_total.append(url)
                        except Exception as e:
                            print(str(e))

                
                print(r_total)
                if r_total:
                    return list(r_total) # Convert set to list before returning

                else : 
                    return json.dumps("mynigga")
                #print(G + '['.rjust(8, '.') + ' {} ]'.format(str(len(r_total))))

            elif r_sc == 404:
                await self.send_error_message("404 MY  NIGGA")
                #print(R + '['.rjust(9, '.') + ' Not Found ]' + W)
            else:
                await self.send_error_message("ERRRROOORRR")
        except Exception as e:
            await self.send_error_message(str(e))  # Convert the exception to a string

    async def sitemap(self , sm_url):
        sm_total = []
        #print(f'{G}[+] {C}Looking for sitemap.xml{W}', end='', flush=True)
        try:
            sm_rqst = requests.get(sm_url, headers=user_agent, verify=False, timeout=10)
            sm_sc = sm_rqst.status_code
            if sm_sc == 200:
                #print(G + '['.rjust(8, '.') + ' Found ]' + W)
                #print(f'{G}[+] {C}Extracting sitemap Links{W}', end='', flush=True)
                sm_page = sm_rqst.content
                sm_soup = bs4.BeautifulSoup(sm_page, 'xml')
                links = sm_soup.find_all('loc')
                for url in links:
                    url = url.get_text()
                    print(url)
                    if url is not None:
                        sm_total.append(url)

                print(sm_total)
                return list(sm_total)

                #sm_total = set(sm_total)
                #print(G + '['.rjust(7, '.') + ' {} ]'.format(str(len(sm_total))))
            elif sm_sc == 404:
                #print(R + '['.rjust(8, '.') + ' Not Found ]' + W)
                await self.send_error_message("404 MY  NIGGA")
            else:
                #print(f'{R}{"[".rjust(8, ".")} Status Code : {sm_sc} ]{W}')
                await self.send_error_message("ERRRROOORRR")
        except Exception as e:
            #print(f'\n{R}[-] Exception : {C}{e}{W}')
            await self.send_error_message(str(e))

    async def css(self,soup,target):
        css_total = []
        css = soup.find_all('link', href=True)

        for link in css:
            url = link.get('href')
            if url is not None and '.css' in url:
                css_total.append(self.url_filter(target, url))

        return list(css_total)

    async def js(self,soup,target):
        js_total = []
        scr_tags = soup.find_all('script', src=True)

        for link in scr_tags:
            url = link.get('src')
            if url is not None and '.js' in url:
                tmp_url = self.url_filter(target, url)
                if tmp_url is not None:
                    js_total.append(tmp_url)

        return list(js_total)

    async def internal_links(self,soup,target):
        int_total = []

        ext = tldextract.extract(target)
        domain = ext.registered_domain

        links = soup.find_all('a')
        for link in links:
            url = link.get('href')
            if url is not None:
                if domain in url:
                    int_total.append(url)

        return list(int_total)

    async def external_links(self,soup,target):
        ext_total = []

        ext = tldextract.extract(target)
        domain = ext.registered_domain

        links = soup.find_all('a')
        for link in links:
            url = link.get('href')
            if url is not None:
                if domain not in url and 'http' in url:
                    ext_total.append(url)

        return list(ext_total)

    async def images(self,soup,target):
        img_total = []
        image_tags = soup.find_all('img')

        for link in image_tags:
            url = link.get('src')
            if url is not None and len(url) > 1:
                img_total.append(self.url_filter(target, url))

        return list(img_total)
    

