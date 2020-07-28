# vtscan
VirusTotal File Scanner CLI Tool

# Virus Total API Key
This tool requires that you first get a API Key from Virus Total:
1. Create a free account on [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Once verified, log in -> Click on avatar on top right -> API Key
3. Set the API key to an environment variable called VT_API_KEY
# Installation
````
% python3 -m pip install virustotal-api
````
# Usage
````
usage: vtscan [-h] [--verbose] [--links] [--browser BROWSER] file

positional arguments:
  file                  File to scan

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -v
  --links, -L
  --browser BROWSER, -b BROWSER
                        Browser to launch for Virus Total Info or other
                        searches
  ````

# Sample output
````
% python3 vtscan.py ~/Downloads/setup.exe
.: Details :.
- md5: a75bbfe51f2495bce794bb5a943b4838
- sha1: 9a24bcbcf58d8ab25d9e915399c9be51ac1837c3
- sha256: a162696a92cbd87626741a0a680844f6b7c134601705884d1957a29f76b3b4e4
- Permalink: https://www.virustotal.com/file/a162696a92cbd87626741a0a680844f6b7c134601705884d1957a29f76b3b4e4/analysis/1578238813/

.: File :.
- File: setup.exe
- Path: /home/tquinn/Downloads

.: Virus Total Summary :.
- Detections: 0 out of 71 (100% pass)
~
````

# Alternatives
1. Virus Total official [cli utility](https://github.com/VirusTotal/vt-cli)
