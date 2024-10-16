# HadesCodeScanner v1.0

Just a simple code audit tool to help with...code audits!


## Usage:

```
usage: HadesCodeScanner.py [-h] [--language LANGUAGE] [--custom-patterns [CUSTOM_PATTERNS ...]] [--custom-strings [CUSTOM_STRINGS ...]] [--semgrepreport SEMGREPREPORT] [--semgreponly] [directory]

Scan source code for potential vulnerabilities.

positional arguments:
  directory             Directory containing source code.

options:
  -h, --help            show this help message and exit
  --language LANGUAGE   Programming language (e.g., java, php, asp, csharp, python, c_cpp, javascript).
  --custom-patterns [CUSTOM_PATTERNS ...]
                        Custom patterns for vulnerabilities in the format "Description::Regex".
  --custom-strings [CUSTOM_STRINGS ...]
                        Custom interesting strings to search for.
  --semgrepreport SEMGREPREPORT
                        Path to Semgrep JSON report file.
  --semgreponly         Only display Semgrep report.

```

## Install

1. Install semgrep (e.g. with docker: ```https://semgrep.dev/docs/getting-started/quickstart``` )
2. Clone the repository ```git clone https://github.com/jvesiluoma/HadesScanner.git```
3. Go to the directory containing your sources.
4. Run semgrep against the source files (in this case *.java) to generate a report, e.g. ```docker run --rm -v /something/something/sources:/src semgrep/semgrep semgrep --config=auto --include='*.java' --json /src > semgrep-report.json```
5. Run the scanner to the directory of your choosing, e.g. ```python3 ~/HadesCodeScanner/HadesCodeScanner.py --language java ./ --semgrepreport=semgrep-report.json``` or just to view the semgrep report with ```python3 ~/HadesCodeScanner/HadesCodeScanner.py --semgrepreport=semgrep-report.json --semgreponly```
6. After the HadesCodeScanner has run for a while you can check the Web UI from http://127.0.0.1:5000/

