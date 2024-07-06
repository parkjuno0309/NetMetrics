# NetMetrics

NetMetrics is a Python application designed for network exploration and security auditing. It takes a list of domains as input, probes these domains in various ways, and generates a detailed report on each domain's network characteristics and security features. The final output is a JSON dictionary that details key network metrics for each domain, such as IP addresses and HTTP server types.

## Languages, Libraries, and Frameworks

-   Python
-   JSON
-   openssl
-   telnet
-   nmap
-   nlookup

## Features

-   Customizable domain inputs
-   Report of network characteristics
-   Key network metrics for each domain

## Setup Instructions For Local Development

1. Clone this repository with `git clone https://github.com/parkjuno0309/NetMetrics.git`.
2. Run `pip install -r requirements.txt` to install the necessary libraries.
3. Update the test_websites.txt file to include domains you would like to test.
4. Run the `python3 scan.py [website_list.txt] [output_file]` command to generate json file.
5. Run the `python3 report.py [scan_file.json] [output_file]` command to generate report.
