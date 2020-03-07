# vtscan
VirusTotal File Scanner CLI Tool

# usage
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
