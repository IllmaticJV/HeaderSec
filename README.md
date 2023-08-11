# HeaderSec

## Introduction

`HeaderSec` is a command-line tool designed to analyze HTTP Security Response Headers. It evaluates the headers against recommended values to highlight potential security improvements. `HeaderSec` supports the inspection of both HTTP and HTTPS headers and can process individual URLs or multiple URLs from a file. The included recommended values are based on the OWASP Secure Header Project.

## Features

- Analyzes standard HTTP Security Response Headers.
- Supports both HTTP and HTTPS protocols.
- Multi-threaded analysis for efficient results.
- Color-coded terminal output for clear interpretation.
- Capability to analyze multiple URLs from a file.
- Optional export of results to a text file.

## Installation

1. Ensure you have Python 3.x installed on your system.
2. Clone the repository or download the source code.
3. Install the required packages using the provided `requirements.txt` file:
  ```bash
  git clone https://github.com/IllmaticJV/HeaderSec
  cd HeaderSec
  pip install -r requirements.txt
  ```

## Usage

### Analyze a Single URL

```bash
python HeaderSec.py -u <URL>
```

### Analyze Multiple URLs from a File

```bash
python HeaderSec.py -f <path/to/file.txt>
```

### Save Output to a File

```bash
python HeaderSec.py -u <URL> -o <path/to/output.txt>
```

## Legend

- **Green**: Header is configured correctly.
- **Yellow**: Header is present but should be checked manually.
- **Red**: Header is missing.
