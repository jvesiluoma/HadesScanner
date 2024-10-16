#!/usr/bin/env python3
import os
import re
import sys
import json
import argparse
import subprocess
from flask import Flask, render_template_string, redirect, request, url_for
from pygments import highlight
from pygments.lexers import get_lexer_by_name, TextLexer
from pygments.formatters import HtmlFormatter

# Get the current working directory
current_directory = os.getcwd()

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
        ("XML External Entity (XXE) Injection", r"DocumentBuilderFactory\.newInstance"),
        ("Improper Use of Regular Expressions (ReDoS)", r"Pattern\.compile"),
        ("Reflection-based invocation (Possible Code Injection)", r"Method\.invoke"),
        ("Trusting all certificates (Insecure SSL Configuration)", r"TrustManager\[\]"),
        ("SQL Query execution without prepared statements (Possible SQL Injection)", r"Statement\.execute(Query|Update)"),
        ("Logging sensitive information (Information Exposure)", r"(log|logger)\.log(Level\.(INFO|WARNING|SEVERE),\s*\"[^\"]*password"),
        ("Deserialization using XStream (Possible Insecure Deserialization)", r"XStream\.fromXML"),
        ("Unvalidated Redirects (Possible Open Redirect)", r"response\.sendRedirect"),
        ("Using Object.equals() for sensitive information comparison (Possible Timing Attack)", r"\.equals\("),
    ],
    'php': [
        ("Use of eval (Possible Code Injection)", r"\beval\s*\("),
        ("SQL Query Concatenation (Possible SQL Injection)", r"\b(mysqli_query|mysql_query)\s*\(.*\.\$"),
        ("Inclusion of Remote Files (Possible File Inclusion Vulnerability)", r"\b(include|require)(_once)?\s*\(.*\$_"),
        ("Use of exec (Possible Command Execution)", r"\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\("),
        ("Use of md5 without salt (Weak Hash Function)", r"\bmd5\s*\("),
        ("Use of unserialize on untrusted data (Possible Deserialization Vulnerability)", r"\bunserialize\s*\(.*\$_"),
        ("Hard-coded password (Credential Exposure)", r"\$.*(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]"),
        ("Use of base64_decode (Possible Obfuscated Code)", r"\bbase64_decode\s*\("),
        
        # Additions
        ("Use of preg_replace with /e modifier (Possible Code Injection)", r"\bpreg_replace\s*\(.*\b/e\b"),
        ("Use of system functions for file upload (Possible File Upload Vulnerability)", r"\bmove_uploaded_file\s*\("),
        ("Use of fopen with untrusted data (Possible Path Traversal)", r"\bfopen\s*\(.*\$_"),
        ("Use of file_get_contents with untrusted data (Possible Remote File Inclusion)", r"\bfile_get_contents\s*\(.*\$_"),
        ("Direct output of user input (Possible XSS)", r"\b(printf|echo)\s*\(.*\$_"),
        ("Use of random_bytes for cryptographic purposes (Weak Random Number Generator)", r"\brandom_bytes\s*\("),
        ("Use of exec with untrusted data (Possible Command Injection)", r"\b(exec|shell_exec)\s*\(.*\$_"),
    ],
    'asp': [
        ("Use of Eval (Possible Code Injection)", r"\bEval\s*\("),
        ("SQL Query Concatenation (Possible SQL Injection)", r"\".*\"\s*\&\s*"),
        ("Hard-coded password (Credential Exposure)", r"(password|passwd|pwd)\s*=\s*\"[^\"]+\""),
        ("Use of Execute (Possible Command Execution)", r"\bExecute\s*\("),
        ("Use of Response.Write with untrusted input (Possible XSS)", r"Response\.Write\s*\(.*\&\s*\$_"),
        ("Inclusion of Remote Files (File Inclusion Vulnerability)", r"\b(Server\.Execute|Server\.Transfer)\s*\(.*\$_"),
        ("Use of Request.QueryString without validation (Possible Input Manipulation)", r"Request\.QueryString\s*\("),
        ("Use of Session variables for sensitive data (Credential Exposure)", r"Session\(\".*(password|passwd|pwd)"),
        ("Insecure file handling functions (Possible Path Traversal)", r"\b(FileSystemObject|FSO)\.OpenTextFile\s*\(.*\$_"),
    ],
    'csharp': [
        ("Use of Process.Start with untrusted input (Possible Command Injection)", r"Process\.Start\s*\("),
        ("SQL Query Concatenation (Possible SQL Injection)", r"\".*\"\s*\+\s*"),
        ("Hard-coded password (Credential Exposure)", r"(password|passwd|pwd)\s*=\s*\"[^\"]+\""),
        ("Hard-coded connection string (Credential Exposure)", r"ConnectionString\s*=\s*\"[^\"]+\""),
        ("Disabling SSL certificate validation (Insecure SSL/TLS Configuration)", r"ServicePointManager\.ServerCertificateValidationCallback\s*=\s*"),
        ("Direct output to response without encoding (Possible XSS)", r"Response\.Write\s*\(.*\)"),
        ("Unsanitized LDAP queries (Possible LDAP Injection)", r"DirectorySearcher\.Filter\s*=\s*.*"),
        ("Unsanitized file paths (Possible Path Traversal)", r"File\.(ReadAllText|WriteAllText|Open|Delete|Exists)\s*\(.*\)"),
        ("Dynamic assembly loading (Possible Code Injection)", r"Assembly\.Load\s*\("),
        ("Use of MD5CryptoServiceProvider (Weak Hash Function)", r"new\s+MD5CryptoServiceProvider\s*\("),
        ("Use of SHA1CryptoServiceProvider (Weak Hash Function)", r"new\s+SHA1CryptoServiceProvider\s*\("),
        ("Use of BinaryFormatter.Deserialize (Possible Insecure Deserialization)", r"BinaryFormatter\.Deserialize\s*\("),
        ("Use of HttpWebRequest with AllowAutoRedirect set to true (Open Redirect)", r"HttpWebRequest\s+.*AllowAutoRedirect\s*=\s*true"),
        ("Use of concatenated SQL queries (Possible SQL Injection)", r"(CommandText|ExecuteNonQuery|ExecuteReader)\s*=\s*\".*\"\s*\+\s*"),
        ("Use of System.Random (Insecure Random Number Generator)", r"new\s+Random\s*\("),
        ("Use of SoapFormatter.Deserialize (Possible Insecure Deserialization)", r"SoapFormatter\.Deserialize\s*\("),
        ("Use of DES encryption (Weak Encryption Algorithm)", r"DESCryptoServiceProvider\s*\("),
        ("Use of RC2 encryption (Weak Encryption Algorithm)", r"RC2CryptoServiceProvider\s*\("),
        ("Execution of commands through cmd.exe (Possible Command Injection)", r"Process\.Start\s*\(\s*\"cmd\.exe\""),
        ("Reflection-based invocation (Possible Code Injection)", r"Invoke\s*\("),
        ("XML External Entity (XXE) Injection", r"XmlReader\.Create\s*\("),
        ("XML External Entity (XXE) Injection", r"XmlDocument\.Load\s*\("),
        ("Unvalidated Redirects (Possible Open Redirect)", r"Response\.Redirect\s*\("),
        ("Dangerous File Uploads (Possible Remote Code Execution)", r"HttpPostedFile\.SaveAs\s*\("),
        ("Improper Use of Regular Expressions (ReDoS)", r"Regex\s*\("),
    ],
    'python': [
        ("Use of eval (Possible Code Injection)", r"\beval\s*\("),
        ("Use of exec (Possible Code Execution)", r"\bexec\s*\("),
        ("SQL Query Concatenation (Possible SQL Injection)", r"\".*\"\s*\+\s*"),
        ("Pickle load on untrusted data (Possible Deserialization Vulnerability)", r"pickle\.load\s*\("),
        ("Hard-coded password (Credential Exposure)", r"(password|passwd|pwd)\s*=\s*[\'\"][^\'\"]+[\'\"]"),
        ("Use of MD5 (Weak Hash Function)", r"hashlib\.md5\s*\("),
        ("Use of SHA1 (Weak Hash Function)", r"hashlib\.sha1\s*\("),
        ("Use of YAML load on untrusted data (Possible Deserialization Vulnerability)", r"yaml\.load\s*\("),
        ("Use of subprocess with shell=True (Possible Command Injection)", r"subprocess\.run\s*\(.*shell\s*=\s*True"),
        ("Use of os.system (Possible Command Injection)", r"os\.system\s*\("),
        ("Use of input() in Python 2 (Possible Command Injection)", r"\binput\s*\("),
        ("Use of marshal (Possible Insecure Deserialization)", r"marshal\.load\s*\("),
        ("Direct file access with open() (Possible Path Traversal)", r"\bopen\s*\(.*\$_"),
        ("Use of execfile (Possible Code Injection)", r"\bexecfile\s*\("),
        ("Use of urllib without validation (Insecure URL Handling)", r"urllib\.(urlopen|request)\s*\("),
    ],
    'c_cpp': [
        ("Use of gets (Possible Buffer Overflow)", r"\bgets\s*\("),
        ("Use of strcpy without bounds checking (Possible Buffer Overflow)", r"\bstrcpy\s*\("),
        ("Use of sprintf (Possible Buffer Overflow)", r"\bsprintf\s*\("),
        ("Use of system (Possible Command Execution)", r"\bsystem\s*\("),
        ("Use of strcat without bounds checking (Possible Buffer Overflow)", r"\bstrcat\s*\("),
        ("Use of fscanf without bounds checking (Possible Buffer Overflow)", r"\bfscanf\s*\("),
        ("Use of sscanf without bounds checking (Possible Buffer Overflow)", r"\bsscanf\s*\("),
        ("Hard-coded password (Credential Exposure)", r"(password|passwd|pwd)\s*=\s*['\"]?[^'\";]+['\"]?"),
        ("Use of malloc without sizeof (Possible Memory Allocation Issue)", r"\bmalloc\s*\([^s]*\)"),
        ("Use of strncpy with potential off-by-one error", r"\bstrncpy\s*\("),
        ("Use of realloc without proper handling (Possible Memory Leak or Crash)", r"\brealloc\s*\("),
        ("Unchecked return value of memory allocation functions (Potential Memory Issue)", r"\b(malloc|calloc|realloc)\s*\("),
        ("Integer overflow/underflow in arithmetic operations", r"\b[+\-*\/]\s*[^;]*\b(int|short|long|unsigned)\b"),
        ("Format string vulnerability in printf-like functions", r"\b(printf|fprintf|snprintf|vfprintf)\s*\([^,]*\$"),
        ("Use of free on non-heap memory (Possible Double Free or Invalid Free)", r"\bfree\s*\(.*\)"),
        ("Use of strcmp with untrusted input (Possible Buffer Overflow)", r"\bstrcmp\s*\("),
        ("Use of alloca (Possible Stack Overflow)", r"\balloca\s*\("),
        ("Direct pointer arithmetic (Possible Memory Corruption)", r"\*\s*\(.*\+"),
        ("Uninitialized variables (Possible Undefined Behavior)", r"\b(int|char|float|double)\s+[^=;]+\s*;"),
    ],
    'lua': [
        ("Use of load or loadstring (Possible Code Injection)", r"\b(load|string)\s*\("),
        ("Use of eval-like functions (Possible Code Injection)", r"\beval\s*\("),
        ("Use of os.execute (Possible Command Injection)", r"\bos\.execute\s*\("),
        ("Use of io.popen (Possible Command Execution)", r"\bio\.popen\s*\("),
        ("Use of dofile (Possible File Inclusion Vulnerability)", r"\bdofile\s*\("),
        ("Use of require with untrusted data (Possible File Inclusion)", r"\brequire\s*\(.*\$_"),
        ("Use of insecure random number generator (Use a cryptographic RNG for sensitive data)", r"\bmath\.random\s*\("),
        ("Pickle or unserialize on untrusted data (Possible Deserialization Vulnerability)", r"\bunserialize\s*\("),
        ("Use of insecure file operations (Possible Path Traversal)", r"\bio\.open\s*\(.*\$_"),
        ("Untrusted input in loadfile (Possible Remote File Inclusion)", r"\bloadfile\s*\("),
        ("Insecure use of setfenv (Scope Manipulation Vulnerability)", r"\bsetfenv\s*\("),
        ("Insecure use of debug library (Possible Privilege Escalation)", r"\bdebug\.(getinfo|getlocal|setlocal|setmetatable|traceback)\s*\("),
        ("Hard-coded password (Credential Exposure)", r"(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]"),
        ("Insecure use of table.concat with untrusted data (Possible Injection)", r"\btable\.concat\s*\(.*\$_"),
        ("Use of package.loadlib (Dynamic Library Loading Vulnerability)", r"\bpackage\.loadlib\s*\("),
        ("Use of collectgarbage (Possible Denial of Service)", r"\bcollectgarbage\s*\("),
        ("Use of untrusted data in coroutines (Possible Denial of Service or Control Hijack)", r"\bcoroutine\.create\s*\("),
        ("Unvalidated user input in string formatting (Format String Vulnerability)", r"\bstring\.format\s*\(.*\$_"),
    ],
    'javascript': [
        ("Use of eval (Possible Code Injection)", r"\beval\s*\("),
        ("Use of innerHTML (Possible XSS Vulnerability)", r"\.innerHTML\s*="),
        ("Use of document.write (Possible XSS Vulnerability)", r"document\.write\s*\("),
        ("Use of setTimeout or setInterval with string argument (Possible Code Injection)", r"\b(setTimeout|setInterval)\s*\(.*['\"].*['\"]"),
        ("Use of Function constructor (Possible Code Injection)", r"\bFunction\s*\("),
        ("Use of unescape (Potential Obfuscated Code)", r"\bunescape\s*\("),
        ("Use of localStorage or sessionStorage without validation (Sensitive Data Exposure)", r"(localStorage|sessionStorage)\.setItem\s*\("),
        ("Use of window.location without validation (Open Redirect)", r"window\.location\s*=\s*"),
        ("Direct access to DOM nodes via document.getElementById (Potential DOM Clobbering)", r"document\.getElementById\s*\("),
        ("Use of jQuery.html() with untrusted data (Possible XSS Vulnerability)", r"\$\.html\s*\("),
        ("Use of dangerouslySetInnerHTML in React (Possible XSS Vulnerability)", r"dangerouslySetInnerHTML\s*="),
        ("Use of XMLHttpRequest without CORS handling (Cross-Origin Resource Sharing Issues)", r"XMLHttpRequest\s*\("),
        ("Use of Object.prototype without hasOwnProperty (Prototype Pollution Vulnerability)", r"Object\.prototype\.[^h]\w*"),
    ],
}

# List of interesting strings to look for (case-insensitive)
default_interesting_strings = [
    # Credentials and Authentication
    "pass", "password", "passwd", "pwd", "username", "user", "api", "apikey",
    "secret", "token", "key", "private", "credential", "auth", "authenticate",
    "authorization", "password_hash", "password_verify", "bcrypt", "argon2", "scrypt",

    # Encryption and Security
    "encrypt", "decrypt", "ssl", "tls", "cert", "certificate", "cipher", "nonce", "iv",
    "crypto", "crypt", "rand", "random", "urandom", "drand",

    # Debugging and Logging
    "debug", "logger", "log", "trace", "dump", "backtrace", "console.log",

    # User Privileges
    "admin", "root", "chmod", "chown", "master", "slave",

    # Malicious or Suspicious Activity
    "hack", "bypass", "vulnerable", "exploit", "malicious", "insecure", "backdoor",
    "leak", "expose", "sensitive", "hardcoded", "plaintext",

    # Input Validation
    "unvalidated", "unchecked", "unsafe", "unsanitized",

    # Command Execution
    "shell", "command", "execute", "exec", "system", "injection", "eval", "Function(", "spawn", "child_process",

    # Code Vulnerabilities
    "format", "printf", "sprintf", "deserialization", "serialize", "deserialize",
    "buffer", "overflow", "underflow", "rce", "xxe", "sqli", "csrf", "xss",
    "ldap", "heapoverflow", "stackoverflow", "formatstring",

    # File System and OS Operations
    "alloc", "free", "memcpy", "fopen", "fs", "open", "close", "chmod", "chroot",
    "mount", "umount", "file", "read", "write", "unlink", "pipe", "dir",

    # Network and Protocols
    "ftp", "http", "https", "ssh", "scp", "sftp", "netcat", "nmap", "wireshark",
    "proxy", "hook", "telnet", "rdp", "vnc", "WebSocket", "XMLHttpRequest", "fetch", "socket", "request", "response",

    # Web and Scripting Vulnerabilities
    "onload", "onclick", "onerror", "onsubmit", "onmouseover", "iframe", "embed",
    "form", "input", "script", "innerHTML", "outerHTML", "document.write", 
    "base64", "data:", "javascript:", "vbscript:", "expression(",
    "alert", "prompt", "confirm", "content-security-policy", "x-frame-options", 
    "x-xss-protection", "x-content-type-options", "strict-transport-security", 
    "referrer-policy", "permissions-policy", "dangerouslySetInnerHTML",

    # Network Configuration and Libraries
    "dns", "net", "tls", "http", "https", "url", "cluster", "dgram", "stream", "zlib",
    "querystring",

    # Timing and Race Conditions
    "race", "thread", "mutex", "semaphore", "deadlock", "lock", "unlock",
    "time", "gettimeofday", "clock", "sleep", "setTimeout", "setInterval",

    # File Inclusion/Path Traversal
    "require(", "import", "export", "module.exports", "__dirname", "__filename", 
    "path", "resolve", "basename", "dirname", "relative",

    # Environment Variables and Sensitive Data Exposure
    "process.env", "Buffer", "JSON.parse", "JSON.stringify", "env", "dotenv", "config",
]

# Global dictionaries to store findings grouped by type
vulnerabilities = {}
interesting_findings = {}
semgrep_findings = {}

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


    # Skip .strings.txt files to prevent duplicate processing
    if "interesting_strings.txt" in file_path or "possible_vulnerabilities.txt" in file_path:
        return


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


def is_binary_file(filepath):
    """
    Determines if a file is binary.
    """
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(1024)
            if b'\0' in chunk:
                return True
            else:
                return False
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return False




def scan_directory(directory, language, custom_patterns, custom_strings, customsearch=False):
    """
    Scans the directory for source files and performs vulnerability scanning and interesting string scanning.
    """
    file_extensions = {
        'java': ('.java',),
        'php': ('.php', '.php3', '.php4', '.php5', '.phtml', '.inc'),
        'asp': ('.asp', '.aspx', '.ascx'),
        'csharp': ('.cs', '.vb', '.cshtml', '.vbhtml'),
        'python': ('.py',),
        'c_cpp': ('.c', '.cpp', '.h', '.hpp', '.cc', '.cxx', '.hh', '.hxx'),
        'javascript': ('.js', '.jsx', '.mjs', '.ts', '.tsx'),
        'html': ('.html', '.htm', '.xhtml', '.jsp', '.asp', '.aspx'),
        'lua': ('.lua', '.wlua'),
    }

    dangerous_patterns = dangerous_patterns_by_language.get(language, [])
    dangerous_patterns.extend(custom_patterns)

    interesting_strings = default_interesting_strings + custom_strings

    if customsearch:
        print("Performing custom search on all files...")
        for root, _, files in os.walk(directory):
            for filename in files:
                file_path = os.path.join(root, filename)
                # Skip already generated .strings.txt files
                if filename.endswith('.strings.txt'):
                    continue

                # Check if the file is binary
                if is_binary_file(file_path):
                    # Run 'strings' command and save output
                    output_file = f"{file_path}.strings.txt"
                    try:
                        with open(output_file, 'w', encoding='utf-8') as outfile:
                            subprocess.run(['strings', file_path], stdout=outfile)
                        print(f"Extracted strings from binary file: {file_path}")
                        # Scan the output file for interesting strings
                        scan_for_interesting_strings(output_file, interesting_strings)
                    except Exception as e:
                        print(f"Error processing binary file {file_path}: {e}")
                else:
                    # For text files, scan directly
                    scan_for_interesting_strings(file_path, interesting_strings)
        # After processing, save the results
        save_results()
    else:
        # Existing code for scanning source files
        # Determine file extensions based on language
        extensions = file_extensions.get(language, ())
        if not extensions:
            print(f"Unsupported language: {language}")
            sys.exit(1)

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

def parse_semgrep_report(semgrep_report_path):
    """
    Parses the Semgrep JSON report and stores the findings.
    """
    global semgrep_findings
    try:
        with open(semgrep_report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Handle errors
        errors = data.get('errors', [])
        for error in errors:
            message = error.get('message', 'No message provided')
            path = error.get('path', 'Unknown path')
            spans = error.get('spans', [])
            for span in spans:
                file_path = span.get('file', path)
                # Prepend current directory to file path
                file_path = os.path.abspath(os.path.join(current_directory, file_path))
                line_number = span.get('start', {}).get('line', 0)
                finding = {
                    'file_path': file_path,
                    'line_number': line_number,
                    'line_content': message,
                    'message': message,
                    'severity': 'Error',
                    'cwe': None,
                    'owasp': None,
                    'owasp_link': None,
                    'impact': None,
                }
                semgrep_findings.setdefault('Semgrep Error', []).append(finding)

        # Handle results
        results = data.get('results', [])
        for result in results:
            check_id = result.get('check_id', 'Semgrep Finding')
            extra = result.get('extra', {})
            message = extra.get('message', 'No message provided')
            path = result.get('path')
            # Prepend current directory to file path
            path = os.path.abspath(os.path.join(current_directory, path))
            line_number = result.get('start', {}).get('line', 0)
            line_content = extra.get('lines', '').strip()
            severity = extra.get('severity', 'INFO').upper()
            metadata = extra.get('metadata', {})
            cwe_list = metadata.get('cwe', [])
            owasp_list = metadata.get('owasp', [])
            impact = metadata.get('impact', None)
            references = metadata.get('references', [])

            # Extract CWE numbers from cwe_list
            cwe_numbers = []
            for cwe_item in cwe_list:
                match = re.search(r'CWE-(\d+)', cwe_item)
                if match:
                    cwe_numbers.append(match.group(1))

            # Extract OWASP info
            owasp_items = owasp_list

            # Extract OWASP link from references if available
            owasp_link = None
            for ref in references:
                if 'owasp.org' in ref:
                    owasp_link = ref
                    break

            finding = {
                'file_path': path,
                'line_number': line_number,
                'line_content': line_content,
                'message': message,
                'severity': severity,
                'cwe': cwe_numbers,
                'owasp': owasp_items,
                'owasp_link': owasp_link,
                'impact': impact,
            }
            semgrep_findings.setdefault(check_id, []).append(finding)

    except Exception as e:
        print(f"Error parsing Semgrep report: {e}")
        sys.exit(1)

def create_app(scan_directory):
    """
    Creates and configures the Flask application.
    """
    app = Flask(__name__)
    app.config['SCAN_DIRECTORY'] = os.path.abspath(scan_directory)

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
              <a class="navbar-brand" href="#">HadesCodeScanner</a>
              <div class="navbar-nav">
                <a class="nav-item nav-link active" href="{{ url_for('vulnerabilities_view') }}">Vulnerabilities</a>
                <a class="nav-item nav-link" href="{{ url_for('interesting_strings_view') }}">Interesting Strings</a>
                <a class="nav-item nav-link" href="{{ url_for('semgrep_view') }}">Semgrep Findings</a>
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
                                    {% set clean_file_path = finding.file_path.replace('/src', '', 1) %}
                                    <tr>
                                        <td>
                                            <a href="{{ url_for('view_file', file_path=clean_file_path, line_number=finding.line_number, language=language) }}" target="_blank">
                                                {{ clean_file_path }}
                                            </a>
                                        </td>
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
                    <a href="{{ url_for('semgrep_view') }}" class="btn btn-secondary">Go to Semgrep Findings</a>
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
              <a class="navbar-brand" href="#">HadesCodeScanner</a>
              <div class="navbar-nav">
                <a class="nav-item nav-link" href="{{ url_for('vulnerabilities_view') }}">Vulnerabilities</a>
                <a class="nav-item nav-link active" href="{{ url_for('interesting_strings_view') }}">Interesting Strings</a>
                <a class="nav-item nav-link" href="{{ url_for('semgrep_view') }}">Semgrep Findings</a>
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
                                    {% set clean_file_path = finding.file_path.replace('/src', '', 1) %}
                                    <tr>
                                        <td>
                                            <a href="{{ url_for('view_file', file_path=clean_file_path, line_number=finding.line_number, language=language) }}" target="_blank">
                                                {{ clean_file_path }}
                                            </a>
                                        </td>
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
                    <a href="{{ url_for('semgrep_view') }}" class="btn btn-secondary">Go to Semgrep Findings</a>
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

    @app.route('/semgrep')
    def semgrep_view():
        # Color mapping based on severity
        severity_colors = {
            'CRITICAL': 'danger',
            'HIGH': 'danger',
            'MEDIUM': 'warning',
            'LOW': 'info',
            'INFO': 'secondary',
            'ERROR': 'danger',
            'WARNING': 'warning',
        }

        # Get the current working directory
        current_directory = os.getcwd()

        semgrep_html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Semgrep Findings</title>
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
            <style>
                body { padding-top: 70px; }
                .navbar { position: fixed; top: 0; width: 100%; }
                .table-container { margin-top: 20px; }
                .footer { margin-top: 20px; }
                .badge { font-size: 100%; }
                .card-header a { color: #fff; text-decoration: underline; }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
              <a class="navbar-brand" href="#">HadesCodeScanner</a>
              <div class="navbar-nav">
                <a class="nav-item nav-link" href="{{ url_for('vulnerabilities_view') }}">Vulnerabilities</a>
                <a class="nav-item nav-link" href="{{ url_for('interesting_strings_view') }}">Interesting Strings</a>
                <a class="nav-item nav-link active" href="{{ url_for('semgrep_view') }}">Semgrep Findings</a>
              </div>
            </nav>
            <div class="container">
                <h1 class="mt-4">Semgrep Findings</h1>
                {% for check_id, findings in semgrep_findings.items() %}
                    <div class="table-container">
                        <h2 onclick="toggleVisibility('semgrep-{{ loop.index }}')" style="cursor: pointer;">
                            {{ check_id }} ({{ findings|length }})
                            <span class="badge badge-{{ severity_colors.get(findings[0].severity, 'secondary') }}">{{ findings[0].severity }}</span>
                        </h2>
                        <div id="semgrep-{{ loop.index }}" style="display: none;">
                            {% for finding in findings %}
                            {% set clean_file_path = finding.file_path.replace('/src', '', 1) %}
                            <div class="card mb-3">
                                <div class="card-header text-white bg-{{ severity_colors.get(finding.severity, 'secondary') }}">
                                    {{ finding.message }}
                                </div>
                                <div class="card-body">
                                    <p>
                                        <strong>Severity:</strong> {{ finding.severity }}<br>
                                        {% if finding.cwe %}
                                            <strong>CWE:</strong>
                                            {% for cwe_id in finding.cwe %}
                                                <a href="https://cwe.mitre.org/cgi-bin/jumpmenu.cgi?id={{ cwe_id }}">CWE-{{ cwe_id }}</a>{% if not loop.last %}, {% endif %}
                                            {% endfor %}
                                            <br>
                                        {% endif %}
                                        {% if finding.owasp %}
                                            <strong>OWASP:</strong>
                                            {% for owasp_item in finding.owasp %}
                                                {{ owasp_item }}{% if not loop.last %}, {% endif %}
                                            {% endfor %}
                                            {% if finding.owasp_link %}
                                                (<a href="{{ finding.owasp_link }}" target="_blank">Reference</a>)
                                            {% endif %}
                                            <br>
                                        {% endif %}
                                        {% if finding.impact %}
                                            <strong>Impact:</strong> {{ finding.impact }}<br>
                                        {% endif %}
                                        <strong>File:</strong> 
                                        <a href="{{ url_for('view_file', file_path=current_directory + clean_file_path, line_number=finding.line_number, language=language) }}" target="_blank">
                                            {{ current_directory + clean_file_path }}
                                        </a><br>
                                        <strong>Line:</strong> {{ finding.line_number }}
                                    </p>
                                    <pre><code>{{ finding.line_content|e }}</code></pre>
                                </div>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                {% endfor %}
                <div class="footer">
                    <a href="{{ url_for('vulnerabilities_view') }}" class="btn btn-primary">Go to Vulnerabilities</a>
                    <a href="{{ url_for('interesting_strings_view') }}" class="btn btn-secondary">Go to Interesting Strings</a>
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
        return render_template_string(semgrep_html, semgrep_findings=semgrep_findings, language=app.config['LANGUAGE'], severity_colors=severity_colors, current_directory=current_directory)

    @app.route('/view_file')
    def view_file():
        file_path = request.args.get('file_path')
        line_number = int(request.args.get('line_number', 0))
        language = request.args.get('language')
        base_dir = os.path.abspath(app.config['SCAN_DIRECTORY'])

        # Resolve the absolute path
        abs_file_path = os.path.abspath(os.path.join(current_directory, file_path))

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
                style='default',  # Changed style for better readability
                linenospecial=0,
                cssclass='codehilite',
            )
            highlighted_code = highlight(code, lexer, formatter)

            # Modify CSS to change line number color and background
            custom_style = '''
            <style>
                pre.codehilite { background-color: #f8f8f8; }
                .codehilite .linenos { color: #888; background-color: #f0f0f0; }
                .codehilite .linenodiv { color: #888; background-color: #f0f0f0; }
                .codehilite .hll { background-color: #ffffcc; }
            </style>
            '''

            return custom_style + highlighted_code + f'''
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
    print("HadesCodeScan v1.0\n")
    parser = argparse.ArgumentParser(description='Scan source code for potential vulnerabilities.')
    parser.add_argument('directory', nargs='?', default=None, help='Directory containing source code.')
    parser.add_argument('--language', help='Programming language (e.g., java, php, asp, csharp, python, c_cpp, javascript).')
    parser.add_argument('--custom-patterns', nargs='*', default=[], help='Custom patterns for vulnerabilities in the format "Description::Regex".')
    parser.add_argument('--custom-strings', nargs='*', default=[], help='Custom interesting strings to search for.')
    parser.add_argument('--semgrepreport', help='Path to Semgrep JSON report file.')
    parser.add_argument('--customsearch', action='store_true', help='Perform a custom search on all files, including binaries, and extract strings from them.')
    parser.add_argument('--semgreponly', action='store_true', help='Only display Semgrep report.')
    args = parser.parse_args()

    app = create_app(args.directory if args.directory else '.')

    if args.semgrepreport:
        print(f"Parsing Semgrep report: {args.semgrepreport}")
        parse_semgrep_report(args.semgrepreport)
        if args.semgreponly:
            # Start the Flask web server
            app.config['LANGUAGE'] = args.language if args.language else 'text'
            print("Starting the web server...")
            app.run(debug=False)
            return

    if args.customsearch:
        if not args.directory:
            print("Error: '--customsearch' requires a directory.")
            parser.print_help()
            sys.exit(1)
        language = None
        app_language = 'text'
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
        print("4")
        if not args.semgreponly:
            print(f"Scanning directory: {args.directory}")
            scan_directory(
                args.directory,
                language,
                custom_patterns,
                custom_strings,
                customsearch=args.customsearch
            )
            print("\nScan completed.")
            print("Results saved to 'possible_vulnerabilities.txt' and 'interesting_strings.txt'.")
    elif args.directory and args.language:
        language = args.language.lower()
        app_language = language
        print("2aaa")
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
            app_language = 'cpp'
        elif language in ['javascript', 'js']:
            language = 'javascript'
            app_language = 'javascript'
        elif language == 'lua':
            language = 'lua'
            app_language = 'lua'
        else:
            print(f"Unsupported language: {language}")
            sys.exit(1)
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
        print("4")
        if not args.semgreponly:
            print(f"Scanning directory: {args.directory}")
            scan_directory(
                args.directory,
                language,
                custom_patterns,
                custom_strings,
                customsearch=args.customsearch
            )
            print("\nScan completed.")
            print("Results saved to 'possible_vulnerabilities.txt' and 'interesting_strings.txt'.")
    else:
        parser.print_help()
        sys.exit(1)

    print("5")
    # Start the Flask web server
    print("Starting the web server...")
    app.run(debug=False)


if __name__ == '__main__':
    main()
