# AsyncMailChecker
## The Ultimate Asynchronous Email Security Assessment Tool

AsyncMailChecker is an advanced asynchronous DNS-based email security assessment tool built in Python. Leveraging the power of asynchronous DNS resolution via `aiodns` and an intuitive Streamlit graphical user interface (GUI), this tool efficiently analyses SPF, DKIM, and DMARC records across multiple domains simultaneously. It provides detailed results, historical data analysis, and rich interactive charts to enhance your email security monitoring capabilities.

## Overview
AsyncMailChecker rapidly evaluates the email security posture of multiple domains through asynchronous DNS queries. This approach significantly reduces the time required for checks compared to traditional synchronous methods, making it ideal for large-scale domain assessments. The tool identifies missing or misconfigured SPF, DKIM, and DMARC records, assisting security teams and administrators in promptly addressing email security weaknesses.

The application features a user-friendly Streamlit GUI, allowing easy interaction and visualization of results. Users can upload domain lists, manage DNS query settings, and produce comprehensive reports effortlessly.

## Requirements

- **Python 3.11 or higher**
- Dependencies can be installed using pip:

```bash
pip install streamlit aiodns pandas altair setuptools
```
(Don't forget to use a virtual environment!)

## Key Features

### Asynchronous DNS Queries
- Accelerated DNS queries using asynchronous concurrency
- Customizable DNS timeout and retry settings
- Support for custom DNS nameservers

### Comprehensive Email Security Checks
- **SPF** record parsing and validation, including recursive mechanism extraction (e.g., `include`, `redirect`, `ip4/ip6`)
- **DKIM** record verification across common selectors
- **DMARC** record discovery and detailed policy analysis (`p`, `fo`, `rua`, `ruf`, `adkim`, `aspf`)

### Streamlit-Powered Interactive GUI
- User-friendly interface for easy upload and management of domain lists
- Real-time progress updates and verbose logging options
- Interactive data tables summarizing SPF, DKIM, and DMARC record statuses

### Historical Data Analysis
- Option to save historical aggregated statistics
- Timeline charts generated from historical CSV data for tracking security posture improvements over time

### Rich Interactive Charts
- Presence matrices clearly indicating SPF, DKIM, and DMARC statuses
- Grouped bar charts displaying record presence or absence
- DMARC-specific charts visualizing policy distributions and forensic options (`fo`)
- Combo-based donut charts and stacked bars showing various domain security combinations

### Export and Reporting
- Export results as detailed CSV reports
- Historical CSV data aggregation for long-term analysis

## Usage
Launch AsyncMailChecker directly through Streamlit:

```bash
streamlit run AsyncMailChecker.py
```

Alternatively, if you prefer not to deploy a public server, use the following command:

```bash
streamlit run AsyncMailChecker.py --server.headless true --server.address "<host ip>"
```

Upload a `.txt` file containing your list of domains (line-separated) to begin the analysis. The GUI will guide you through configuring your desired settings, performing the scans, and visualizing the results.

## Example
- Load your domain list into AsyncMailChecker via the Streamlit GUI.
- Adjust DNS query settings such as recursion depth and concurrency levels.
- Initiate DNS checks and observe real-time progress.
- View comprehensive interactive summaries and download CSV reports upon completion.

## Screenshots

_(Placeholders for images showcasing the tool's interface, charts, and summary outputs)_

- GUI Overview (upload and settings)
- Interactive Records Matrix
- Grouped Bar Chart for SPF/DKIM/DMARC Statuses
- DMARC Policy Distribution Chart
- Historical Timeline Analysis

## Integration and Extensibility
AsyncMailChecker can integrate into broader security assessment frameworks or operate as a standalone solution. The CSV output enables easy ingestion into SIEM tools or further data analysis platforms.

## Recommendations
Regularly use AsyncMailChecker to audit and maintain the email security posture of your organization's domain assets. It provides critical insights to proactively address vulnerabilities and strengthen overall email security.

## Contributions
Contributions, improvements, or issue reports are welcome. Please submit pull requests or issues directly to the repository.

## Author
Developed by Fr4n  
@JUMPSEC

