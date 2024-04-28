import json
import sys
import time
import subprocess
import logging
import socket
import maxminddb

command = sys.argv
source_file = str(command[1])
output_file = str(command[2])
timeout_default = 2

class ScanClass:
    def __init__(self, source_file, output_file):
        self.results_map = {}
        self.scan_results_map = {}
        self.passing_results = ""
        self.is_hsts_enabled = False
        self.available_scans = ["scan_time", "ipv4_addresses", "ipv6_addresses", "http_server", "insecure_http", "redirect_to_https", "hsts", "tls_versions", "root_ca", "rdns_names", "rtt_range", "geo_locations"]
        logging.basicConfig(level=logging.ERROR)

        with open(source_file, 'r') as file:
            lines = file.read().splitlines()
            file.close()

        for line in lines:
            scan_outcome = self.perform_scan(line)
            self.results_map[line] = scan_outcome

        with open(output_file, 'w') as file:
            json.dump(self.results_map, file, indent=4)
            file.close()

    def perform_scan(self, url):
        self.scan_results_map = {}

        for scan in self.available_scans:
            try:
                scan_method = getattr(self, scan)
                self.scan_results_map[scan] = scan_method(url)
            except AttributeError:
                logging.error(f"Scan method {scan} not implemented for URL {url}")
            except (FileNotFoundError, OSError) as error:
                logging.error(f"{scan} could not be executed for URL {url} due to: {error}")
        return self.scan_results_map

    def execute_command(self, command, timeout_duration):
        output = ""
        retries = 0
        max_retries = 3

        while retries < max_retries:
            try:
                output = subprocess.check_output(command, stderr=subprocess.DEVNULL, timeout = timeout_duration).decode('utf-8')
                if output:
                    break
            except subprocess.TimeoutExpired:
                logging.warning(f"Timeout expired for: {command[0]} on {command[-1]}. Retry {retries+1}/{max_retries}")
                retries += 1
            except subprocess.CalledProcessError as e:
                logging.error(f"Error executing: {command[0]} on {command[-1]}. {e}; Retry {retries+1}/{max_retries}")
                retries += 1

        if retries == max_retries and not output:
            logging.error(f"Failed to execute: {command[0]} on {command[-1]} after {max_retries} attempts.")

        return output

    def scan_time(self, url):
        return time.time()

    def ipv4_addresses(self, url):
        dns_servers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", "198.101.242.72", "176.103.130.130"]
        unique_ipv4s = set()
        for dns_server in dns_servers:
            command = ["nslookup", url, dns_server]
            lookup_result = self.execute_command(command, timeout_default)
            if lookup_result:
                lines = lookup_result.splitlines()
                for line in lines:
                    if not line.endswith(dns_server):
                        if "Address: " in line:
                            ip_address = line.split("Address: ")[1].strip()
                            if ":" not in ip_address:
                                unique_ipv4s.add(ip_address)
                        elif "address: " in line:
                            ip_address = line.split("address: ")[1].strip()
                            if ":" not in ip_address:
                                unique_ipv4s.add(ip_address)
        
        return list(unique_ipv4s)

    def ipv6_addresses(self, url):
        dns_servers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", "198.101.242.72", "176.103.130.130"]
        unique_ipv6s = set()
        for dns_server in dns_servers:
            command = ["nslookup", "-type=AAAA", url, dns_server]
            lookup_result = self.execute_command(command, timeout_default)

            # LOCAL
            if lookup_result and "has AAAA address" in lookup_result:
                for line in lookup_result.splitlines():
                    if "AAAA" in line and "has AAAA address" in line:
                        ip_address = line.split("has AAAA address")[1].strip()
                        if ip_address:
                            unique_ipv6s.add(ip_address)

            # MOORE
            # if lookup_result:
            #     record_found = False
            #     for line in lookup_result.splitlines():
            #         if 'Non-authoritative answer:' in line:
            #             record_found = True
            #         elif record_found and line.startswith('Address:') and ':' in line:
            #             # This assumes IPv6 addresses contain ':', which is a valid assumption
            #             ip_address = line.split('Address:')[1].strip()
            #             if ip_address:
            #                 unique_ipv6s.add(ip_address)
        
        return list(unique_ipv6s)
    
    def http_server(self, url):
        url = "http://" + url
        command = ["curl", "-I", "--http2", url]
        result = self.execute_command(command, timeout_default)

        if result != "":
            self.passing_results = result
            split_result = result.split("Server: ")
            if len(split_result) == 1:
                split_result = result.split("server: ")
                if len(split_result) == 1:
                    return None
            del split_result[0]
            server = split_result[0].split("\r\n")
            answer = server[0]
            return answer
        else:
            return None

    def insecure_http(self, url):
        if self.passing_results != "":
            return True
        else:
            return False
        
    def redirect_to_https(self, url):
        if not url.startswith("http://"):
            url = "http://" + url
        
        max_redirects = 10
        for _ in range(max_redirects):
            command = ["curl", "-I", url]
            header = self.execute_command(command, timeout_default)
            if not header:
                return False
            
            if any(code in header for code in ['301', '302', '303', '307', '308']):
                if "Location: " in header:
                    location = header.split("Location: ")[1].split("\r\n")[0].strip()
                    if location.startswith("https://"):
                        return True
                    url = location
                else:
                    return False
            else:
                return False
        return False
    
    def hsts(self, url):
        if not url.startswith("https://"):
            url = "https://" + url
        
        command = ["curl", "-I", url]
        header = self.execute_command(command, timeout_default)
        if header:
            if "Strict-Transport-Security:" in header or "strict-transport-security:" in header:
                return True
            else:
                if "Location: " in header:
                    location = header.split("Location: ")[1].split("\r\n")[0].strip()
                    if location.startswith("https://"):
                        return self.hsts(location)
                    else:
                        return False
                else:
                    return False
        else:
            return False

    def tls_versions(self, url):
        tls_versions_supported = []
        url_string = url + ":443"

        args_nmap = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", url]
        result_nmap = self.execute_command(args_nmap, 10)
        if result_nmap:
            for tls_version in ["TLSv1.0", "TLSv1.1", "TLSv1.2"]:
                if tls_version in result_nmap:
                    tls_versions_supported.append(tls_version)
        
        args_openssl = ["openssl", "s_client", "-tls1_3", "-connect", url_string]
        try:
            result_openssl = subprocess.check_output(args_openssl, stderr=subprocess.DEVNULL, timeout=2, input=b'').decode("utf-8")
            if "TLSv1.3" in result_openssl or "New, TLSv1.3," in result_openssl:
                tls_versions_supported.append("TLSv1.3")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

        return tls_versions_supported

    def root_ca(self, url):
        command = ["openssl", "s_client", "-connect", f"{url}:443"]
        try:
            result = subprocess.check_output(command, input=b'\n', stderr=subprocess.STDOUT, timeout=timeout_default).decode("utf-8")

            if "O=" in result:
                lines = result.splitlines()
                for line in reversed(lines):
                    if "O=" in line:
                        org_name_start = line.find("O=") + 2
                        org_name_end = line.find(", ", org_name_start) if ", " in line[org_name_start:] else len(line)
                        root_ca_name = line[org_name_start:org_name_end].strip()
                        return root_ca_name
                return None
            else:
                return None
        except subprocess.TimeoutExpired:
            return None
        except subprocess.CalledProcessError:
            return None

    def rdns_names(self, url):
        ipv4_addresses = self.scan_results_map.get("ipv4_addresses", [])
        rdns_names_list = []

        for ip_address in ipv4_addresses:
            command = ["nslookup", "-type=PTR", ip_address]
            result = self.execute_command(command, timeout_default)

            if result:
                lines = result.splitlines()
                ptr_records = [line for line in lines if "name = " in line]

                for record in ptr_records:
                    name_part = record.split('name = ')[1]
                    name = name_part.strip().rstrip('.')
                    if name:
                        rdns_names_list.append(name)
        return rdns_names_list

    def rtt_range(self, url):
        ipv4_addresses = self.scan_results_map.get("ipv4_addresses", [])
        ports = [80, 443, 22]
        rtt_results = []

        for ip_address in ipv4_addresses:
            for port in ports:
                try:
                    start_time = time.time()
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(timeout_default)
                        sock.connect((ip_address, port))
                        sock.close()
                    end_time = time.time()
                    rtt = (end_time - start_time) * 1000
                    rtt_results.append(rtt)
                except (socket.timeout, socket.error):
                    continue
        
        if not rtt_results:
            return None
        
        min_rtt = int(min(rtt_results))
        max_rtt = int(max(rtt_results))
        return [min_rtt, max_rtt]


    def geo_locations(self, url):
        ipv4_addresses = self.scan_results_map.get("ipv4_addresses", [])
        unique_locations = set()

        with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
            for ip_address in ipv4_addresses:
                loc_data = reader.get(ip_address)
                if loc_data is None:
                    continue
                
                parts = []

                city_name = loc_data.get('city', {}).get('names', {}).get('en')
                if city_name:
                    parts.append(city_name)

                subdivisions = loc_data.get('subdivisions', [])
                if subdivisions:
                    subdivision_name = subdivisions[0].get('names', {}).get('en')
                    if subdivision_name:
                        parts.append(subdivision_name)

                country_name = loc_data.get('country', {}).get('names', {}).get('en')
                if country_name:
                    parts.append(country_name)
                
                if len(parts) == 3:
                    unique_locations.add(", ".join(parts))
        return list(unique_locations)



s = ScanClass(source_file, output_file)