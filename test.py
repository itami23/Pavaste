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


import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_website(base_url, max_depth=None, depth=0):
    # Dictionary to store URLs and their response codes
    response_codes = {}
    # Set to store all visited links
    all_links = set()

    if max_depth is not None and depth > max_depth:
        return response_codes, all_links

    # Skip if the link has already been visited
    if base_url in all_links:
        return response_codes, all_links

    try:
        response = requests.get(base_url)
        response.raise_for_status()  # Check for HTTP errors
    except requests.exceptions.RequestException as e:
        print(f"Error while fetching {base_url}: {e}")
        response_codes[base_url] = str(e)
        return response_codes, all_links

    # Mark the current link as visited
    all_links.add(base_url)

    # Store the response code for the current URL
    response_codes[base_url] = response.status_code

    # Parse the HTML content
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all anchor tags (links) in the HTML content
    for anchor in soup.find_all('a', href=True):
        link = anchor['href']

        # Normalize the link by joining with the base URL
        full_link = urljoin(base_url, link)

        # Remove any fragments (#) from the link
        parsed_link = urlparse(full_link)._replace(fragment='').geturl()

        # Skip links outside the base URL domain
        if not parsed_link.startswith(base_url):
            continue

        # Recursively crawl the new link
        sub_response_codes, all_links = crawl_website(parsed_link, max_depth, depth + 1)

        # Update response_codes with the results from the recursive call
        response_codes.update(sub_response_codes)

    return response_codes, all_links

if __name__ == "__main__":
    # Replace 'https://example.com' with the base URL of the website to crawl
    base_url = 'https://emsi.ma'

    # Set the maximum depth (optional, set to None for unlimited depth)
    max_depth = 2

    response_codes, all_links = crawl_website(base_url, max_depth)

    # Print all the links and their response codes gathered from the website
    for link, code in response_codes.items():
        print(f"URL: {link} - Response Code: {code}")

