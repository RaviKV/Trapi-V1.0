import os
import sys
import json
import xml.etree.ElementTree as ET
import requests
import threading
import re
from queue import Queue

class TrApi:
    def __init__(self):
        self.api_url = ''
        self.word_list = []
        self.endpoints = []
        self.results = {}

    def print_banner(self):
        # Simple ASCII banner
        print(r"""
 ______       
|__  __|       /\      ______   || 
   || _ ___   //\\    ||____ |
   || |'___| //__\\   ||____||  ||
   || ||    //____\\  ||_____|  ||
   || ||   //      \\ ||        ||
                           
        """)
        print("Welcome to TrApi - API Vulnerability Assessment Tool\n")

    def download_dependencies(self):
        print("Downloading necessary dependencies...")
        # List of Python package dependencies
        dependencies = ["requests"]

        # Install Python dependencies
        for dep in dependencies:
            os.system(f"pip install {dep}")
        
        print("Dependencies installed successfully.")
        print("\nDependencies required:")
        for dep in dependencies:
            print(f"- {dep}")

    def download_common_wordlist(self):
        print("Downloading common word list...")
        wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api-endpoints.txt"
        wordlist_path = "common_wordlist.txt"
        try:
            response = requests.get(wordlist_url)
            with open(wordlist_path, 'wb') as f:
                f.write(response.content)
            print(f"Common word list downloaded to {wordlist_path}")
        except Exception as e:
            print(f"Failed to download common word list: {e}")

    def load_word_list(self, custom_path=None):
        if custom_path:
            if custom_path.endswith('.txt'):
                with open(custom_path, 'r') as f:
                    self.word_list = [line.strip() for line in f.readlines()]
            elif custom_path.endswith('.xml'):
                tree = ET.parse(custom_path)
                root = tree.getroot()
                self.word_list = [elem.text for elem in root.findall('.//word')]
            elif custom_path.endswith('.json'):
                with open(custom_path, 'r') as f:
                    self.word_list = json.load(f)
        else:
            print("Using predefined word list...")
            # Hardcoded word list
            self.word_list = ['login', 'register', 'user', 'profile', 'data', 'admin']
        
    def get_user_input(self):
        # Display instructions
        self.print_banner()
        print("Please ensure you have a 'wordlists' folder for custom word lists.")
        input("Press Enter to continue...")

        # Download dependencies
        self.download_dependencies()

        # Download common word list
        self.download_common_wordlist()

        # Choose custom word list or predefined
        while True:
            choice = input("Do you want to use a custom word list? (y/n): ").lower()
            if choice in ['y', 'n']:
                break
            else:
                print("Invalid input. Please enter 'y' or 'n'.")
        
        if choice == 'y':
            while True:
                custom_path = input("Enter the path to your custom word list (.txt, .xml, .json): ")
                if os.path.exists(custom_path) and custom_path.endswith(('.txt', '.xml', '.json')):
                    self.load_word_list(custom_path)
                    break
                else:
                    print("Invalid path or file type. Please enter a valid path to a .txt, .xml, or .json file.")
        else:
            self.load_word_list()
        
        # Get API URL
        while True:
            self.api_url = input("Enter the API URL: ").strip()
            if self.validate_api_url(self.api_url):
                break
            else:
                print("Invalid URL. Please enter a valid API URL. Example: https://api.example.com")
        
        # Choose output format
        while True:
            self.output_format = input("Enter the output format (json/xml): ").lower()
            if self.output_format in ['json', 'xml']:
                break
            else:
                print("Invalid input. Please enter 'json' or 'xml'.")
        
        # Get output file path
        while True:
            self.output_path = input(f"Enter the path to save the output ({self.output_format}): ")
            if os.path.dirname(self.output_path) == '' or os.path.exists(os.path.dirname(self.output_path)):
                break
            else:
                print("Invalid path. Please enter a valid file path.")

    def validate_api_url(self, url):
        return re.match(r'^https?://[^\s/$.?#].[^\s]*$', url)

    def enumerate_endpoints(self):
        print("Starting endpoint enumeration...")
        queue = Queue()

        def worker():
            while not queue.empty():
                word = queue.get()
                url = f"{self.api_url}/{word}"
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        print(f"Found endpoint: {url}")
                        self.endpoints.append(url)
                except requests.exceptions.RequestException:
                    pass
                queue.task_done()
        
        # Start threads for enumeration
        for word in self.word_list:
            queue.put(word)

        threads = []
        for _ in range(10):  # Number of threads
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)

        queue.join()

    def vulnerability_scan(self):
        print("Starting OWASP Top 10 Vulnerability Scan...")
        queue = Queue()

        def owasp_checks(endpoint):
            # Vulnerability checks
            return {
                "SQL Injection": self.sql_injection_check(endpoint),
                "Broken Authentication": self.broken_authentication_check(endpoint),
                "Sensitive Data Exposure": self.sensitive_data_exposure_check(endpoint),
                "XML External Entities": self.xml_external_entities_check(endpoint),
                "Broken Access Control": self.broken_access_control_check(endpoint),
                "Security Misconfiguration": self.security_misconfiguration_check(endpoint),
                "Cross-Site Scripting (XSS)": self.xss_check(endpoint),
                "Insecure Deserialization": self.insecure_deserialization_check(endpoint),
                "Using Components with Known Vulnerabilities": self.known_vulnerabilities_check(endpoint),
                "Insufficient Logging & Monitoring": self.logging_monitoring_check(endpoint)
            }

        def worker():
            while not queue.empty():
                endpoint = queue.get()
                print(f"Scanning {endpoint}...")
                self.results[endpoint] = owasp_checks(endpoint)
                queue.task_done()
        
        # Start threads for vulnerability scanning
        for endpoint in self.endpoints:
            queue.put(endpoint)

        threads = []
        for _ in range(10):  # Number of threads
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)

        queue.join()

    # Actual vulnerability checks
    def sql_injection_check(self, endpoint):
        test_payload = "' OR '1'='1"
        try:
            response = requests.get(f"{endpoint}?id={test_payload}")
            if "syntax error" not in response.text and response.status_code == 200:
                return "Potential SQL Injection vulnerability"
        except:
            pass
        return "Not vulnerable"

    def broken_authentication_check(self, endpoint):
        try:
            response = requests.get(endpoint, auth=('invalid_user', 'invalid_pass'))
            if response.status_code == 200:
                return "Potential Broken Authentication vulnerability"
        except:
            pass
        return "Not vulnerable"

    def sensitive_data_exposure_check(self, endpoint):
        try:
            response = requests.get(endpoint)
            if "password" in response.text or "creditcard" in response.text:
                return "Potential Sensitive Data Exposure"
        except:
            pass
        return "Not vulnerable"

    def xml_external_entities_check(self, endpoint):
        xml_payload = """<?xml version="1.0"?>
        <!DOCTYPE root [
        <!ELEMENT root ANY >
        <!ENTITY test SYSTEM "file:///etc/passwd" >]><root>&test;</root>"""
        headers = {'Content-Type': 'application/xml'}
        try:
            response = requests.post(endpoint, data=xml_payload, headers=headers)
            if "root:x:" in response.text:
                return "Potential XXE vulnerability"
        except:
            pass
        return "Not vulnerable"

    def broken_access_control_check(self, endpoint):
        try:
            response = requests.get(f"{endpoint}/admin")
            if response.status_code == 200:
                return "Potential Broken Access Control vulnerability"
        except:
            pass
        return "Not vulnerable"

    def security_misconfiguration_check(self, endpoint):
        try:
            response = requests.options(endpoint)
            if "Allow" in response.headers:
                return "Potential Security Misconfiguration vulnerability"
        except:
            pass
        return "Not vulnerable"

    def xss_check(self, endpoint):
        test_payload = "<script>alert('xss')</script>"
        try:
            response = requests.get(f"{endpoint}?q={test_payload}")
            if test_payload in response.text:
                return "Potential Cross-Site Scripting (XSS)"
        except:
            pass
        return "Not vulnerable"

    def insecure_deserialization_check(self, endpoint):
        serialized_payload = "O:8:\"Exploit\":0:{}"
        try:
            response = requests.post(endpoint, data=serialized_payload)
            if response.status_code == 500:
                return "Potential Insecure Deserialization vulnerability"
        except:
            pass
        return "Not vulnerable"

    def known_vulnerabilities_check(self, endpoint):
        try:
            response = requests.get(endpoint)
            if "Server" in response.headers and "Apache/2.4.49" in response.headers['Server']:
                return "Using Components with Known Vulnerabilities"
        except:
            pass
        return "Not vulnerable"

    def logging_monitoring_check(self, endpoint):
        # Placeholder check
        return "Not vulnerable - placeholder for logging & monitoring checks"

    def save_results(self):
        if self.output_format == 'json':
            with open(self.output_path, 'w') as f:
                json.dump(self.results, f, indent=4)
        elif self.output_format == 'xml':
            root = ET.Element("Results")
            for endpoint, findings in self.results.items():
                endpoint_elem = ET.SubElement(root, "Endpoint", url=endpoint)
                for vuln_type, result in findings.items():
                    vuln_elem = ET.SubElement(endpoint_elem, vuln_type.replace(" ", "_"))
                    vuln_elem.text = result
            tree = ET.ElementTree(root)
            tree.write(self.output_path)
        print(f"Results saved to {self.output_path}")

    def run(self):
        # Run all steps
        self.get_user_input()
        self.enumerate_endpoints()
        self.vulnerability_scan()
        self.save_results()

if __name__ == '__main__':
    tool = TrApi()
    tool.run()
