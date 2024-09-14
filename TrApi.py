# Very basic don't use this, it is a test app
import sys
import requests
import json
import re
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QProgressBar, QMessageBox, QFileDialog)
from PyQt5.QtCore import QThread, pyqtSignal

# Worker thread to perform endpoint enumeration
class EndpointEnumerationThread(QThread):
    progress_signal = pyqtSignal(int)  # Signal to update progress
    result_signal = pyqtSignal(str, list)

    def __init__(self, api_url):
        super().__init__()
        self.api_url = api_url

    def run(self):
        # List of common endpoints and extensions
        wordlist = [
            "", "index", "home", "api", "users", "products", "orders", "login", "register", "admin", "status", "health",
            "swagger.json", "openapi.json", "robots.txt", "sitemap.xml", "static", "assets", "js", "css"
            # Add more wordlists and extensions as needed
        ]

        discovered_endpoints = []

        total_requests = len(wordlist) * 4  # Testing each endpoint with multiple HTTP methods
        completed_requests = 0

        for word in wordlist:
            for method in ['GET', 'POST', 'PUT', 'DELETE']:
                url = f"{self.api_url.rstrip('/')}/{word}"
                try:
                    response = requests.request(method, url, timeout=3)
                    if response.status_code == 200 or response.status_code == 204:
                        discovered_endpoints.append(url)
                except requests.RequestException:
                    continue

                completed_requests += 1
                # Update progress
                progress_value = int((completed_requests / total_requests) * 100)  # Enumeration progress from 0 to 100
                self.progress_signal.emit(progress_value)

        # Emit results
        result_text = "Discovered Endpoints:\n" + "\n".join(discovered_endpoints) if discovered_endpoints else "No endpoints were discovered."
        self.result_signal.emit(result_text, discovered_endpoints)

# Worker thread to perform vulnerability assessment
class VulnerabilityAssessmentThread(QThread):
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(str, dict)

    def __init__(self, api_url, endpoints):
        super().__init__()
        self.api_url = api_url
        self.endpoints = endpoints

    def run(self):
        checks = [
            self.check_broken_object_level_auth,
            self.check_broken_user_authentication,
            self.check_excessive_data_exposure,
            self.check_lack_of_resources_rate_limiting,
            self.check_broken_function_level_auth,
            self.check_mass_assignment,
            self.check_security_misconfiguration,
            self.check_injection,
            self.check_improper_assets_management,
            self.check_insufficient_logging_monitoring,
        ]

        progress_step = 100 // len(checks)  # Vulnerability assessment progress from 0 to 100
        results = {"endpoints": self.endpoints}

        for i, check in enumerate(checks):
            result = check(self.api_url)
            results[check.__name__] = result
            self.progress_signal.emit((i + 1) * progress_step)  # Vulnerability assessment progress

        # Ensure all values are strings before emitting
        result_str = {k: str(v) for k, v in results.items()}
        self.result_signal.emit("\n".join(result_str.values()), result_str)

    def check_broken_object_level_auth(self, url):
        test_url = f"{url}/api/v1/users/1"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                return "Broken Object Level Authorization: Vulnerability Found (Access to object directly)"
            return "Broken Object Level Authorization: No direct access to object."
        except requests.RequestException:
            return "Broken Object Level Authorization: Error in performing the test."

    def check_broken_user_authentication(self, url):
        test_url = f"{url}/api/v1/protected-resource"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                return "Broken User Authentication: Vulnerability Found (Resource accessible without authentication)"
            return "Broken User Authentication: Proper authentication required."
        except requests.RequestException:
            return "Broken User Authentication: Error in performing the test."

    def check_excessive_data_exposure(self, url):
        test_url = f"{url}/api/v1/users"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and "password" in response.text.lower():
                return "Excessive Data Exposure: Vulnerability Found (Sensitive data exposed)"
            return "Excessive Data Exposure: No sensitive data exposed."
        except requests.RequestException:
            return "Excessive Data Exposure: Error in performing the test."

    def check_lack_of_resources_rate_limiting(self, url):
        test_url = f"{url}/api/v1/users"
        try:
            for _ in range(20):  # Attempt a burst of 20 requests
                response = requests.get(test_url)
                if response.status_code != 200:
                    break
            else:
                return "Lack of Resources & Rate Limiting: Vulnerability Found (No rate limiting)"
            return "Lack of Resources & Rate Limiting: Rate limiting detected."
        except requests.RequestException:
            return "Lack of Resources & Rate Limiting: Error in performing the test."

    def check_broken_function_level_auth(self, url):
        test_url = f"{url}/api/v1/admin"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                return "Broken Function Level Authorization: Vulnerability Found (Admin endpoint accessible)"
            return "Broken Function Level Authorization: Admin endpoint not accessible."
        except requests.RequestException:
            return "Broken Function Level Authorization: Error in performing the test."

    def check_mass_assignment(self, url):
        test_url = f"{url}/api/v1/users"
        payload = {"username": "testuser", "role": "admin"}
        try:
            response = requests.post(test_url, json=payload)
            if response.status_code == 200 and "admin" in response.text.lower():
                return "Mass Assignment: Vulnerability Found (Mass assignment possible)"
            return "Mass Assignment: No mass assignment detected."
        except requests.RequestException:
            return "Mass Assignment: Error in performing the test."

    def check_security_misconfiguration(self, url):
        test_url = f"{url}/api/v1/users"
        try:
            response = requests.options(test_url)
            if "PUT" in response.text or "DELETE" in response.text:
                return "Security Misconfiguration: Vulnerability Found (Dangerous HTTP methods enabled)"
            return "Security Misconfiguration: No dangerous HTTP methods detected."
        except requests.RequestException:
            return "Security Misconfiguration: Error in performing the test."

    def check_injection(self, url):
        test_url = f"{url}/api/v1/users?search=' OR '1'='1"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and "error" not in response.text.lower():
                return "Injection: Vulnerability Found (Possible SQL injection)"
            return "Injection: No SQL injection detected."
        except requests.RequestException:
            return "Injection: Error in performing the test."

    def check_improper_assets_management(self, url):
        test_url = f"{url}/api/v1/deprecated-endpoint"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                return "Improper Assets Management: Vulnerability Found (Deprecated endpoint accessible)"
            return "Improper Assets Management: No deprecated endpoints detected."
        except requests.RequestException:
            return "Improper Assets Management: Error in performing the test."

    def check_insufficient_logging_monitoring(self, url):
        test_url = f"{url}/api/v1/users"
        try:
            response = requests.get(test_url)
            if response.status_code != 200 and "error" not in response.text.lower():
                return "Insufficient Logging & Monitoring: Vulnerability Found (No detailed error messages)"
            return "Insufficient Logging & Monitoring: Error messages are properly managed."
        except requests.RequestException:
            return "Insufficient Logging & Monitoring: Error in performing the test."

# Main application window
class ApiVulnerabilityApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('TrApi V1.0')
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        self.url_label = QLabel('Enter API URL:')
        self.url_input = QLineEdit()
        layout.addWidget(self.url_label)
        layout.addWidget(self.url_input)

        self.scan_button = QPushButton('Start Scan')
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        self.enum_progress_bar = QProgressBar()
        self.enum_progress_bar.setFormat('Enumeration Progress: %p%')
        layout.addWidget(self.enum_progress_bar)

        self.scan_progress_bar = QProgressBar()
        self.scan_progress_bar.setFormat('Scan Progress: %p%')
        layout.addWidget(self.scan_progress_bar)

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)

        self.setLayout(layout)

    def start_scan(self):
        api_url = self.url_input.text().strip()
        if not self.validate_api_url(api_url):
            QMessageBox.warning(self, "Invalid URL", "Please enter a valid API URL. Example: https://api.example.com")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Output", "", "JSON Files (*.json)")
        if not file_path:
            return

        self.enum_progress_bar.setValue(0)
        self.scan_progress_bar.setValue(0)

        # Start endpoint enumeration
        self.endpoint_thread = EndpointEnumerationThread(api_url)
        self.endpoint_thread.progress_signal.connect(self.update_enum_progress)
        self.endpoint_thread.result_signal.connect(self.handle_enum_results)
        self.endpoint_thread.finished.connect(lambda: self.start_vulnerability_assessment(file_path))
        self.endpoint_thread.start()

        # Pass the file path to the vulnerability assessment thread for saving results
        self.file_path = file_path

    def validate_api_url(self, url):
        return re.match(r'^https?://[^\s/$.?#].[^\s]*$', url)

    def update_enum_progress(self, value):
        self.enum_progress_bar.setValue(value)

    def update_scan_progress(self, value):
        self.scan_progress_bar.setValue(value)

    def handle_enum_results(self, text, endpoints):
        self.results_text.append(text)
        self.endpoints = endpoints

    def start_vulnerability_assessment(self, file_path):
        # Start vulnerability assessment
        self.vuln_thread = VulnerabilityAssessmentThread(self.url_input.text().strip(), self.endpoints)
        self.vuln_thread.progress_signal.connect(self.update_scan_progress)
        self.vuln_thread.result_signal.connect(lambda text, data: self.handle_vuln_results(text, data, file_path))
        self.vuln_thread.start()

    def handle_vuln_results(self, text, results, file_path):
        self.results_text.append(text)
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=4)
        QMessageBox.information(self, "Scan Complete", f"Vulnerability assessment complete. Results saved to {file_path}.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ApiVulnerabilityApp()
    window.show()
    sys.exit(app.exec_())
