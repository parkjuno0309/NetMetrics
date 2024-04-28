import json
import sys
import texttable

def generate_report(input_file, output_file):
    with open(input_file, 'r') as file:
        data = json.load(file)

    with open(output_file, 'w') as out:
        # Part 1
        out.write("Detailed Listings for Each Domain:\n")
        detailed_table = texttable.Texttable(max_width=400)
        detailed_headers = ["Website", "Scan Time", "IPv4 Addresses", "IPv6 Addresses",
                            "HTTP Server", "Insecure HTTP", "Redirect to HTTPS", "HSTS",
                            "TLS Versions", "Root CA", "RDNS Names", "RTT Range", "Geo Locations"]
        keys = ["scan_time", "ipv4_addresses", "ipv6_addresses", "http_server", "insecure_http", "redirect_to_https", "hsts", "tls_versions", "root_ca", "rdns_names", "rtt_range", "geo_locations"]
        detailed_table.header(detailed_headers)
        for website, info in data.items():
            print(website, info)
            row = [website] + [info.get(key, 'N/A') for key in keys]
            detailed_table.add_row(row)
        out.write(detailed_table.draw() + "\n\n")

        # Part 2
        out.write("RTT Ranges Sorted by Minimum RTT:\n")
        rtt_table = texttable.Texttable(max_width=0)
        rtt_table.header(["Website", "RTT Minimum (ms)", "RTT Maximum (ms)"])
        rtt_sorted = sorted(data.items(), key=lambda x: x[1].get("rtt_range", [float('inf'), 0])[0])
        for website, info in rtt_sorted:
            rtt_range = info.get("rtt_range", ["N/A", "N/A"])
            rtt_table.add_row([website, rtt_range[0], rtt_range[1]])
        out.write(rtt_table.draw() + "\n\n")

        # Helper func to summarize and sort info from data
        def summarize_and_sort(data, key):
            summary = {}
            for info in data.values():
                item = info.get(key)
                if item:
                    summary[item] = summary.get(item, 0) + 1
            return sorted(summary.items(), key=lambda x: x[1], reverse=True)
        
        # Part 3
        out.write("Root Certificate Authorities Count:\n")
        ca_table = texttable.Texttable(max_width=0)
        ca_table.header(["Root CA", "Count"])
        for ca, count in summarize_and_sort(data, 'root_ca'):
            ca_table.add_row([ca, count])
        out.write(ca_table.draw() + "\n\n")

        # Part 4
        out.write("Web Server Popularity:\n")
        server_table = texttable.Texttable(max_width=0)
        server_table.header(["Web Server", "Count"])
        for server, count in summarize_and_sort(data, "http_server"):
            server_table.add_row([server, count])
        out.write(server_table.draw() + "\n\n")

        # Part 5
        out.write("Percentage of Scanned Domains Supporting:\n")
        features_summary = percentage_supporting(data)
        features_table = texttable.Texttable(max_width=0)
        features_table.header(["Feature", "Percentage of Domains Supporting"])
        for feature, percentage in features_summary.items():
            features_table.add_row([feature, f"{percentage:.2f}%"])
        out.write(features_table.draw() + "\n\n")

def percentage_supporting(data):
    features_summary = {
        "TLSv1.0": 0, "TLSv1.1": 0, "TLSv1.2": 0, "TLSv1.3": 0,
        "SSLv2": 0, "SSLv3": 0,
        "plain_http": 0, "https_redirect": 0, "hsts": 0, "ipv6": 0
    }
    total_domains = len(data)

    for info in data.values():
        for version in ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSLv2", "SSLv3"]:
            if version in info.get("tls_versions", []):
                features_summary[version] += 1
        if info.get("insecure_http", False):
            features_summary["plain_http"] += 1
        if info.get("redirect_to_https", False):
            features_summary["https_redirect"] += 1
        if info.get("hsts", False):
            features_summary["hsts"] += 1
        if len(info.get("ipv6_addresses", [])) > 0:
            features_summary["ipv6"] += 1

    for key in features_summary:
        features_summary[key] = (features_summary[key] / total_domains) * 100

    return features_summary

if __name__ == "__main__":
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    generate_report(input_path, output_path)