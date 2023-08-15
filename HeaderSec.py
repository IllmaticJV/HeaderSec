#!/usr/bin/env python3

import requests
import argparse
from urllib.parse import urlparse
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from prettytable import PrettyTable
from textwrap import fill
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def print_legend():
    print(colored("Legend:", 'cyan'))
    print(colored("Green  ", 'green') + " - Header is configured correctly.")
    print(colored("Yellow ", 'yellow') + " - Header is present but should be checked manually.")
    print(colored("Red    ", 'red') + " - Header is missing.\n")

def compare_values(actual_value, proposed_value):
    actual_values = Counter(filter(bool, map(str.strip, actual_value.replace(';', ' ').replace(',', ' ').split())))
    proposed_values = Counter(filter(bool, map(str.strip, proposed_value.replace(';', ' ').replace(',', ' ').split())))
    return actual_values == proposed_values

def analyze_header(url, scheme):
    full_url = f"{scheme}://{url}" if not urlparse(url).scheme else url

    try:
        response = requests.get(full_url, timeout=10, verify=False)
    except requests.exceptions.RequestException as e:
        error_message = f"Failed to retrieve {full_url}."
        return None, colored(error_message, 'red')

    headers = response.headers
    return headers, f"Analyzing {full_url}... Status code: {response.status_code}"


def analyze_headers(url):
    schemes = ['http', 'https'] if not urlparse(url).scheme else [urlparse(url).scheme]
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda scheme: analyze_header(url, scheme), schemes))

    # Filter out the accessible headers
    accessible_results = [result for result in results if result[0] is not None]

    # If the accessible results have the same headers, keep only one
    if len(accessible_results) == 2 and headers_equal(accessible_results[0][0], accessible_results[1][0], url):
        results = [accessible_results[0]]

    output_results = []
    output_results.append("\n")

    for headers, message in results:
        output_results.append(colored(message, 'cyan'))

        # If headers is None, then there was an error, so continue to the next result
        if headers is None:
            continue


        table = PrettyTable()
        table.field_names = ["HEADER Name", "Configured Value", "Recommended Value"]


        recommended_headers = {
            'Permissions-Policy': 'accelerometer=(),ambient-light-sensor=(),autoplay=(),battery=(),camera=(),display-capture=(),document-domain=(),encrypted-media=(),fullscreen=(),gamepad=(),geolocation=(),gyroscope=(),layout-animations=(self),legacy-image-formats=(self),magnetometer=(),microphone=(),midi=(),oversized-images=(self),payment=(),picture-in-picture=(),publickey-credentials-get=(),speaker-selection=(),sync-xhr=(self),unoptimized-images=(self),unsized-media=(self),usb=(),screen-wake-lock=(),web-share=(),xr-spatial-tracking=()',
            'Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains',
            'X-Frame-Options': 'deny',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content",
            'X-Permitted-Cross-Domain-Policies': 'none',
            'Referrer-Policy': 'no-referrer',
            'Clear-Site-Data': '"cache","cookies","storage"',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
            'Cache-Control': 'no-store, max-age=0'
        }

        for header, proposed_value in recommended_headers.items():
            actual_value = headers.get(header)
            if actual_value is None:
                row = [colored(header, 'red'), colored("MISSING", 'red'), fill(proposed_value, width=90)]
            elif compare_values(actual_value, proposed_value):
                row = [colored(header, 'green'), fill(actual_value, width=90), fill(proposed_value, width=90)]
            else:
                row = [colored(header, 'yellow'), fill(actual_value, width=90), fill(proposed_value, width=90)]
            table.add_row(row)

        output_results.append(table.get_string())
        output_results.append("\n")

    return output_results

# Function to analyze a file with multiple URLs
def analyze_file(file_path, output_file):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file]

    for url in urls:
        results = analyze_headers(url)
        print_results(results, output_file)

# Function to print the results to the console and output file if provided
def print_results(results, output_file):
    for result in results:
        print(result)
        if output_file:
            with open(output_file, 'a') as file:
                # Add an extra newline character before writing the result
                file.write(result + '\n')


def headers_equal(headers1, headers2, hostname):
    print(colored(f"Analyzing headers for {hostname}...", 'cyan'))
    security_headers = [
        "Permissions-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "X-Permitted-Cross-Domain-Policies",
        "Referrer-Policy",
        "Clear-Site-Data",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cache-Control"
    ]
    
    for header in security_headers:
        value1 = headers1.get(header, "").strip()
        value2 = headers2.get(header, "").strip()
        if value1 != value2:
            print(colored(f"Values for key '{header}' are different: '{value1}' != '{value2}'", 'red'))
            return False

    print(colored(f"HTTP and HTTPS headers are the same for {hostname}",'green'))
    return True


# Main function
def main():
    parser = argparse.ArgumentParser(description="Analyze HTTP Security Response Headers")
    parser.add_argument("-u", "--url", help="URL to analyze")
    parser.add_argument("-f", "--file", help="File containing hostnames/URLs per line")
    parser.add_argument("-o", "--output", help="Output file")
    args = parser.parse_args()
    print_legend() # Print the legend at the start of the script

    if args.url:
        results = analyze_headers(args.url)
        print_results(results, args.output)
    elif args.file:
        analyze_file(args.file, args.output)
    else:
        print("Please provide a URL using -u or a file using -f.")

if __name__ == "__main__":
    main()
