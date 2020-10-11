# Enrich IOC

This python script is useful to enrich the Domain and IP Address IOCs with Passive Total aka RiskIQ & VirusTotal API.

With limitations on scraping the Symantec's sitereview site, this script now uses selenium to scrape the categorization details.

## Pre-requisites:

- Python 3.5+
- Download Chrome Driver compatible with the Browser version you run from https://chromedriver.chromium.org/downloads
  * Unzip and move to /usr/local/bin (MAC OS/Linux) 

## Package Dependencies:

- Install Selenium by running as below,  
```pip install selenium```

Most other package dependencies are by default available with the python installation.

## How-To execute the script:

- Run the script by passing a list of Domains/IPs new-line separated by running as below,  
```python enrich.py -l <list of IPs/Domains>```
  
- Run the script as below for enriching a single IP or a domain,  
```python enrich.py -c <IP or Domain>```
