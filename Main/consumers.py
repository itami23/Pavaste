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






#################################################################################################################################################################




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
            await self.send_json({'error': str(e)})
