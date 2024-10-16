#!/usr/bin/env python3
import os
import re
import sys
import argparse
from flask import Flask, render_template_string, send_from_directory, url_for, redirect, request
from pygments import highlight
from pygments.lexers import get_lexer_by_name, TextLexer
from pygments.formatters import HtmlFormatter

# Mapping of programming languages to dangerous patterns
dangerous_patterns_by_language = {
    'java': [
        ("Use of Runtime.getRuntime().exec (Possible Command Injection)", r"Runtime\.getRuntime\(\)\.exec"),
        ("Use of ProcessBuilder (Possible Command Injection)", r"new\s+ProcessBuilder"),
        ("Deserialization of untrusted data (Possible Insecure Deserialization)", r"new\s+ObjectInputStream"),
        ("SQL Query Concatenation (Possible SQL Injection)", r"\".*\"\s*\+\s*"),
        ("Hard-coded password (Credential Exposure)", r"(password|passwd|pwd)\s*=\s*\"[^\"]+\""),
        ("Use of MD5 (Weak Hash Function)", r"MessageDigest\.getInstance\(\"MD5\"\)"),
        ("Use of SHA1 (Weak Hash Function)", r"MessageDigest\.getInstance\(\"SHA-1\"\)"),
        ("Insecure Random Generator (Use SecureRandom instead)", r"new\s+Random\(\)"),
        ("Use of Cipher in ECB mode (Weak Encryption Mode)", r"Cipher\.getInstance\(\"[A-Za-z0-9]+/ECB/"),
        ("Disabling SSL/TLS Certificate Validation (Insecure SSL Configuration)", r"setHostnameVerifier\s*\("),
    ],
    'php': [
        ("Use of eval (Possible Code Injection)", r"\beval\s*\("),
        ("SQL Query Concatenation (Possible SQL Injection)", r"\bmysqli_query\s*\(.*\.\$"),
        ("Inclusion of Remote Files (Possible File Inclusion Vulnerability)", r"\binclude\s*\(.*\$_"),
        ("Use of exec (Possible Command Execution)", r"\b(exec|system|passthru|shell_exec)\s*\("),
        ("Use of md5 without salt (Weak Hash Function)", r"\bmd5\s*\("),
        ("Use of unserialize on untrusted data (Possible Deserialization Vulnerability)", r"\bunserialize\s*\(.*\$_"),
        ("Hard-coded password (Credential Exposure)", r"\$.*(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]"),
    ],
    'asp': [
        ("Use of Eval (Possible Code Injection)", r"\bEval\s*\("),
        ("SQL Query Concatenation (Possible SQL Injection)", r"\".*\"\s*\+\s*"),
        ("Hard-coded password (Credential Exposure)", r"(password|passwd|pwd)\s*=\s*\"[^\"]+\""),
        ("Use of Execute (Possible Command Execution)", r"\bExecute\s*\("),
    ],
    'csharp': [
        ("Use of Process.Start with untrusted input (Possible Command Injection)", r"Process\.Start\s*\("),
        ("SQL Query Concatenation (Possible SQL Injection)", r"\".*\"\s*\+\s*"),
        ("Hard-coded password (Credential Exposure)", r"(password|passwd|pwd)\s*=\s*\"[^\"]+\""),
        ("Use of MD5CryptoServiceProvider (Weak Hash Function)", r"new\s+MD5CryptoServiceProvider\s*\("),
        ("Use of SHA1CryptoServiceProvider (Weak Hash Function)", r"new\s+SHA1CryptoServiceProvider\s*\("),
    ],
    'python': [
        ("Use of eval (Possible Code Injection)", r"\beval\s*\("),
        ("Use of exec (Possible Code Execution)", r"\bexec\s*\("),
        ("SQL Query Concatenation (Possible SQL Injection)", r"\".*\"\s*\+\s*"),
        ("Pickle load on untrusted data (Possible Deserialization Vulnerability)", r"pickle\.load\s*\("),
        ("Hard-coded password (Credential Exposure)", r"(password|passwd|pwd)\s*=\s*[\'\"][^\'\"]+[\'\"]"),
        ("Use of MD5 (Weak Hash Function)", r"hashlib\.md5\s*\("),
        ("Use of SHA1 (Weak Hash Function)", r"hashlib\.sha1\s*\("),
    ],
    'c_cpp': [
        ("Use of gets (Possible Buffer Overflow)", r"\bgets\s*\("),
        ("Use of strcpy without bounds checking (Possible Buffer Overflow)", r"\bstrcpy\s*\("),
        ("Use of sprintf (Possible Buffer Overflow)", r"\bsprintf\s*\("),
        ("Use of system (Possible Command Execution)", r"\bsystem\s*\("),
        ("Use of strcat without bounds checking (Possible Buffer Overflow)", r"\bstrcat\s*\("),
        ("Use of fscanf without bounds checking (Possible Buffer Overflow)", r"\bfscanf\s*\("),
        ("Use of sscanf without bounds checking (Possible Buffer Overflow)", r"\bsscanf\s*\("),
        ("Hard-coded password (Credential Exposure)", r"(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]"),
    ],
    # Add other languages as needed
}

# List of interesting strings to look for (case-insensitive)
default_interesting_strings = [
    "pass", "password", "passwd", "pwd", "username", "user", "api", "apikey",
    "secret", "token", "key", "private", "credential", "auth", "authenticate",
    "authorization", "encrypt", "decrypt", "ssl", "tls", "cert", "certificate",
    "debug", "admin", "root", "hack", "bypass", "vulnerable", "exploit",
    "malicious", "insecure", "backdoor", "leak", "expose", "sensitive",
    "hardcoded", "plaintext", "disabled", "unvalidated", "unchecked", "unsafe",
    "shell", "command", "execute", "exec", "injection", "eval", "printf",
    "sprintf", "format", "deserialization", "serialize", "deserialize",
    "logging", "logger", "trace", "dump", "ftp", "http", "https", "soap",
    "rest", "connection", "connect", "session", "cipher", "nonce", "iv",
    "master", "slave", "chmod", "chown", "netcat", "nmap", "wireshark",
    "aircrack", "sniffer", "intercept", "spoof", "proxy", "hook", "overflow",
    "corrupt", "rce", "xxe", "sqli", "csrf", "xss", "redirect", "ldap",
    "rdp", "vnc", "telnet", "ssh", "scp", "sftp", "backtrace", "overflow",
    "stack", "heap", "formatstring", "heapoverflow", "stackoverflow",
]

# Global dictionaries to store findings grouped by type
vulnerabilities = {}
interesting_findings = {}

def scan_for_vulnerabilities(file_path, dangerous_patterns):
    """
    Scans a single file for dangerous patterns and stores the results.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_number, line in enumerate(file, start=1):
                for description, pattern in dangerous_patterns:
                    if re.search(pattern, line):
                        finding = {
                            'file_path': file_path,
                            'line_number': line_number,
                            'line_content': line.strip()
                        }
                        vulnerabilities.setdefault(description, []).append(finding)
                        print(f"[!] {description} found in {file_path}, line {line_number}")
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

def scan_for_interesting_strings(file_path, interesting_strings):
    """
    Scans a single file for interesting strings and stores the results.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_number, line in enumerate(file, start=1):
                for keyword in interesting_strings:
                    if re.search(r'\b' + re.escape(keyword) + r'\b', line, re.IGNORECASE):
                        finding = {
                            'file_path': file_path,
                            'line_number': line_number,
                            'line_content': line.strip()
                        }
                        interesting_findings.setdefault(keyword.lower(), []).append(finding)
                        print(f"[i] Interesting string '{keyword}' found in {file_path}, line {line_number}")
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

def scan_directory(directory, language, custom_patterns, custom_strings):
    """
    Scans the directory for source files and performs vulnerability scanning and interesting string scanning.
    """
    file_extensions = {
        'java': '.java',
        'php': '.php',
        'asp': '.asp',
        'csharp': '.cs',
        'python': '.py',
        'c_cpp': ('.c', '.cpp', '.h', '.hpp'),
        # Add other languages and their file extensions as needed
    }

    if language not in file_extensions:
        print(f"Unsupported language: {language}")
        sys.exit(1)

    extensions = file_extensions[language]
    if isinstance(extensions, str):
        extensions = (extensions,)

    dangerous_patterns = dangerous_patterns_by_language.get(language, [])
    dangerous_patterns.extend(custom_patterns)

    interesting_strings = default_interesting_strings + custom_strings

    source_files = []
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith(extensions):
                file_path = os.path.join(root, filename)
                source_files.append(file_path)

    # First, scan for vulnerabilities
    print("Scanning for possible vulnerabilities...")
    for file_path in source_files:
        scan_for_vulnerabilities(file_path, dangerous_patterns)

    # Then, scan for interesting strings
    print("\nScanning for interesting strings...")
    for file_path in source_files:
        scan_for_interesting_strings(file_path, interesting_strings)

    # Save the results to files
    save_results()

def save_results():
    """
    Saves the findings to 'possible_vulnerabilities.txt' and 'interesting_strings.txt'.
    """
    with open("possible_vulnerabilities.txt", 'w') as vulnerabilities_file:
        for description, findings in vulnerabilities.items():
            vulnerabilities_file.write(f"=== {description} ===\n")
            for finding in findings:
                message = f"[!] Found in {finding['file_path']}, line {finding['line_number']}\n"
                vulnerabilities_file.write(message)

    with open("interesting_strings.txt", 'w') as strings_file:
        for keyword, findings in interesting_findings.items():
            strings_file.write(f"=== Interesting String: {keyword} ===\n")
            for finding in findings:
                message = f"[i] Found in {finding['file_path']}, line {finding['line_number']}\n"
                strings_file.write(message)

def create_app(scan_directory):
    """
    Creates and configures the Flask application.
    """
    app = Flask(__name__)
    app.config['SCAN_DIRECTORY'] = scan_directory

    @app.route('/')
    def index():
        return redirect(url_for('vulnerabilities_view'))

    @app.route('/vulnerabilities')
    def vulnerabilities_view():
        vulnerabilities_html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Possible Vulnerabilities</title>
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
            <style>
                body { padding-top: 70px; }
                .navbar { position: fixed; top: 0; width: 100%; }
                .table-container { margin-top: 20px; }
                .table thead th { position: sticky; top: 0; background-color: #fff; }
                .footer { margin-top: 20px; }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
              <a class="navbar-brand" href="#">Code Vulnerability Scanner</a>
              <div class="navbar-nav">
                <a class="nav-item nav-link active" href="{{ url_for('vulnerabilities_view') }}">Vulnerabilities</a>
                <a class="nav-item nav-link" href="{{ url_for('interesting_strings_view') }}">Interesting Strings</a>
              </div>
            </nav>
            <div class="container">
                <h1 class="mt-4">Possible Vulnerabilities</h1>
                {% for description, findings in vulnerabilities.items() %}
                    <div class="table-container">
                        <h2 onclick="toggleVisibility('vuln-{{ loop.index }}')" style="cursor: pointer;">{{ description }} ({{ findings|length }})</h2>
                        <div id="vuln-{{ loop.index }}" style="display: none;">
                            <table class="table table-bordered table-hover">
                                <thead>
                                    <tr>
                                        <th>File Path</th>
                                        <th>Line Number</th>
                                        <th>Code Snippet</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for finding in findings %}
                                    <tr>
                                        <td><a href="{{ url_for('view_file', file_path=finding.file_path, line_number=finding.line_number, language=language) }}" target="_blank">{{ finding.file_path }}</a></td>
                                        <td>{{ finding.line_number }}</td>
                                        <td><code>{{ finding.line_content|e }}</code></td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                {% endfor %}
                <div class="footer">
                    <a href="{{ url_for('interesting_strings_view') }}" class="btn btn-primary">Go to Interesting Strings</a>
                </div>
            </div>
            <script>
                function toggleVisibility(id) {
                    var elem = document.getElementById(id);
                    if (elem.style.display === 'none') {
                        elem.style.display = 'block';
                    } else {
                        elem.style.display = 'none';
                    }
                }
            </script>
        </body>
        </html>
        '''
        return render_template_string(vulnerabilities_html, vulnerabilities=vulnerabilities, language=app.config['LANGUAGE'])

    @app.route('/interesting')
    def interesting_strings_view():
        interesting_html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Interesting Strings</title>
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
            <style>
                body { padding-top: 70px; }
                .navbar { position: fixed; top: 0; width: 100%; }
                .table-container { margin-top: 20px; }
                .table thead th { position: sticky; top: 0; background-color: #fff; }
                .footer { margin-top: 20px; }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
              <a class="navbar-brand" href="#">Code Vulnerability Scanner</a>
              <div class="navbar-nav">
                <a class="nav-item nav-link" href="{{ url_for('vulnerabilities_view') }}">Vulnerabilities</a>
                <a class="nav-item nav-link active" href="{{ url_for('interesting_strings_view') }}">Interesting Strings</a>
              </div>
            </nav>
            <div class="container">
                <h1 class="mt-4">Interesting Strings</h1>
                {% for keyword, findings in interesting_findings.items() %}
                    <div class="table-container">
                        <h2 onclick="toggleVisibility('int-{{ loop.index }}')" style="cursor: pointer;">{{ keyword }} ({{ findings|length }})</h2>
                        <div id="int-{{ loop.index }}" style="display: none;">
                            <table class="table table-bordered table-hover">
                                <thead>
                                    <tr>
                                        <th>File Path</th>
                                        <th>Line Number</th>
                                        <th>Code Snippet</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for finding in findings %}
                                    <tr>
                                        <td><a href="{{ url_for('view_file', file_path=finding.file_path, line_number=finding.line_number, language=language) }}" target="_blank">{{ finding.file_path }}</a></td>
                                        <td>{{ finding.line_number }}</td>
                                        <td><code>{{ finding.line_content|e }}</code></td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                {% endfor %}
                <div class="footer">
                    <a href="{{ url_for('vulnerabilities_view') }}" class="btn btn-primary">Go to Vulnerabilities</a>
                </div>
            </div>
            <script>
                function toggleVisibility(id) {
                    var elem = document.getElementById(id);
                    if (elem.style.display === 'none') {
                        elem.style.display = 'block';
                    } else {
                        elem.style.display = 'none';
                    }
                }
            </script>
        </body>
        </html>
        '''
        return render_template_string(interesting_html, interesting_findings=interesting_findings, language=app.config['LANGUAGE'])

    @app.route('/view_file')
    def view_file():
        file_path = request.args.get('file_path')
        line_number = int(request.args.get('line_number', 0))
        language = request.args.get('language')
        base_dir = os.path.abspath(app.config['SCAN_DIRECTORY'])

        # Security check: Ensure the file is within the scan directory
        abs_file_path = os.path.abspath(file_path)
        if not abs_file_path.startswith(base_dir):
            return "Access denied.", 403

        try:
            with open(abs_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()

            # Get the appropriate lexer
            try:
                lexer = get_lexer_by_name(language)
            except Exception:
                lexer = TextLexer()

            # Use Pygments to highlight the code
            formatter = HtmlFormatter(
                linenos=True,
                full=True,
                hl_lines=[line_number],
                lineanchors='line',
                anchorlinenos=True,
                style='monokai'
            )
            highlighted_code = highlight(code, lexer, formatter)

            return highlighted_code + f'''
            <script>
                window.onload = function() {{
                    var element = document.getElementById('line-{line_number}');
                    if(element) {{
                        element.scrollIntoView();
                        element.style.backgroundColor = '#ffff99';
                    }}
                }};
            </script>
            '''

        except Exception as e:
            return f"Error reading file: {e}", 500

    return app

def main():
    parser = argparse.ArgumentParser(description='Scan source code for potential vulnerabilities.')
    parser.add_argument('directory', help='Directory containing source code.')
    parser.add_argument('--language', required=True, help='Programming language (e.g., java, php, asp, csharp, python, c_cpp).')
    parser.add_argument('--custom-patterns', nargs='*', default=[], help='Custom patterns for vulnerabilities in the format "Description::Regex".')
    parser.add_argument('--custom-strings', nargs='*', default=[], help='Custom interesting strings to search for.')
    args = parser.parse_args()

    language = args.language.lower()
    app_language = language
    if language == 'csharp':
        app_language = 'csharp'
    elif language == 'asp':
        app_language = 'asp'
    elif language == 'python':
        app_language = 'python'
    elif language == 'java':
        app_language = 'java'
    elif language == 'php':
        app_language = 'php'
    elif language in ['c', 'cpp', 'c_cpp']:
        language = 'c_cpp'
        app_language = 'cpp'  # For syntax highlighting
    else:
        print(f"Unsupported language: {language}")
        sys.exit(1)

    app = create_app(args.directory)
    app.config['LANGUAGE'] = app_language

    # Process custom patterns
    custom_patterns = []
    for pattern in args.custom_patterns:
        if '::' in pattern:
            description, regex = pattern.split('::', 1)
            custom_patterns.append((description, regex))
        else:
            print(f"Invalid custom pattern format: {pattern}. Expected 'Description::Regex'.")
            sys.exit(1)

    # Custom interesting strings
    custom_strings = args.custom_strings

    if not os.path.isdir(args.directory):
        print(f"The directory {args.directory} does not exist.")
        sys.exit(1)

    print(f"Scanning directory: {args.directory}")
    scan_directory(args.directory, language, custom_patterns, custom_strings)
    print("\nScan completed.")
    print("Results saved to 'possible_vulnerabilities.txt' and 'interesting_strings.txt'.")

    # Start the Flask web server
    print("Starting the web server...")
    app.run(debug=False)

if __name__ == '__main__':
    main()
