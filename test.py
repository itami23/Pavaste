# import nmap

# def scan_subdomain(subdomain):
#     nm = nmap.PortScanner()
#     nm.scan(subdomain, arguments='-T4 -A -v')

#     open_ports = []
#     for host in nm.all_hosts():
#         for proto in nm[host].all_protocols():
#             lport = nm[host][proto].keys()
#             for port in lport:
#                 if nm[host][proto][port]['state'] == 'open':
#                     open_ports.append(port)

#     return open_ports

# if __name__ == "__main__":
#     subdomain = input("Enter the subdomain to scan: ")
#     open_ports = scan_subdomain(subdomain)

#     if open_ports:
#         print(f"Open ports on {subdomain}: {', '.join(map(str, open_ports))}")
#     else:
#         print("No open ports found.")


# import requests
# from bs4 import BeautifulSoup
# from urllib.parse import urljoin, urlparse

# def crawl_website(base_url, max_depth=None, depth=0):
#     # Dictionary to store URLs and their response codes
#     response_codes = {}
#     # Set to store all visited links
#     all_links = set()

#     if max_depth is not None and depth > max_depth:
#         return response_codes, all_links

#     # Skip if the link has already been visited
#     if base_url in all_links:
#         return response_codes, all_links

#     try:
#         response = requests.get(base_url)
#         response.raise_for_status()  # Check for HTTP errors
#     except requests.exceptions.RequestException as e:
#         print(f"Error while fetching {base_url}: {e}")
#         response_codes[base_url] = str(e)
#         return response_codes, all_links

#     # Mark the current link as visited
#     all_links.add(base_url)

#     # Store the response code for the current URL
#     response_codes[base_url] = response.status_code

#     # Parse the HTML content
#     soup = BeautifulSoup(response.text, 'html.parser')

#     # Find all anchor tags (links) in the HTML content
#     for anchor in soup.find_all('a', href=True):
#         link = anchor['href']

#         # Normalize the link by joining with the base URL
#         full_link = urljoin(base_url, link)

#         # Remove any fragments (#) from the link
#         parsed_link = urlparse(full_link)._replace(fragment='').geturl()

#         # Skip links outside the base URL domain
#         if not parsed_link.startswith(base_url):
#             continue

#         # Recursively crawl the new link
#         sub_response_codes, all_links = crawl_website(parsed_link, max_depth, depth + 1)

#         # Update response_codes with the results from the recursive call
#         response_codes.update(sub_response_codes)

#     return response_codes, all_links

# if __name__ == "__main__":
#     # Replace 'https://example.com' with the base URL of the website to crawl
#     base_url = 'https://emsi.ma'

#     # Set the maximum depth (optional, set to None for unlimited depth)
#     max_depth = 2

#     response_codes, all_links = crawl_website(base_url, max_depth)

#     # Print all the links and their response codes gathered from the website
#     for link, code in response_codes.items():
#         print(f"URL: {link} - Response Code: {code}")



###########################XSS ATTACK TEST###########################################
import requests
from bs4 import BeautifulSoup, SoupStrainer

def load_xss_payloads(file_path):
    payloads = []
    with open(file_path, 'r') as filehandle:
        for line in filehandle:
            xss_payload = line.strip()
            payloads.append(xss_payload)
    return payloads

def scan_for_xss(url, payloads, stop_after_first=False):
    results = []
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for HTTP error status codes
        for payload in payloads:
            data = {}
            for field in BeautifulSoup(response.text, "html.parser", parse_only=SoupStrainer('input')):
                if field.has_attr('name'):
                    if field['name'].lower() == "submit":
                        data[field['name']] = "submit"
                    else:
                        data[field['name']] = payload
            response = requests.post(url, data=data)
            if payload in response.text:
                results.append(payload)
                if stop_after_first:
                    break  # Stop after first payload is found
        return results
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return []

def save_results(filename, results):
    with open(filename, 'w') as filehandle:
        for result in results:
            filehandle.write(result + '\n')

def main():
    xss_payloads = load_xss_payloads("constants/xss_vectors.txt")

    url = input("Enter the URL to scan for XSS vulnerabilities: ")

    stop_option = input("Do you want to stop after the first payload is found? (y/n): ").lower()
    stop_after_first = stop_option == "y"

    xss_vulnerable_payloads = scan_for_xss(url, xss_payloads, stop_after_first)

    if xss_vulnerable_payloads:
        print("XSS Vulnerabilities Found:")
        for payload in xss_vulnerable_payloads:
            print("Payload", payload, "returned in the response")
        
        save_option = input("Do you want to save the results to a file? (y/n): ").lower()
        if save_option == "y":
            filename = input("Enter the filename to save the results: ")
            save_results(filename, xss_vulnerable_payloads)
            print("Results saved to", filename)
    else:
        print("No XSS Vulnerabilities Found.")

if __name__ == "__main__":
    main()






####################GET ALL URLS AND PAGES OF A WEBSITE

# import requests
# from bs4 import BeautifulSoup
# from urllib.parse import urljoin

# def get_all_page_urls(base_url):
#     visited_urls = set()
#     pending_urls = [base_url]
#     all_page_urls = []

#     while pending_urls:
#         current_url = pending_urls.pop(0)
#         if current_url in visited_urls:
#             continue
        
#         try:
#             response = requests.get(current_url)
#             visited_urls.add(current_url)
            
#             if response.status_code == 200:
#                 soup = BeautifulSoup(response.text, 'html.parser')
#                 all_page_urls.append(current_url)

#                 for link in soup.find_all('a', href=True):
#                     absolute_url = urljoin(current_url, link['href'])
#                     if absolute_url.startswith(base_url) and absolute_url not in visited_urls and absolute_url not in pending_urls:
#                         pending_urls.append(absolute_url)
#         except Exception as e:
#             print(f"Error fetching {current_url}: {e}")

#     return all_page_urls

# if __name__ == "__main__":
#     base_url = "https://emsi.ma"
#     page_urls = get_all_page_urls(base_url)

#     for url in page_urls:
#         print(url)



