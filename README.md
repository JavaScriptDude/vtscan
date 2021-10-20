# vtscan
VirusTotal File Scanner CLI Tool

### Virus Total API Key
This tool requires that you first get a API Key from Virus Total:
1. Create a free account on [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Once verified, log in -> Click on avatar on top right -> API Key
3. Set the API key to an environment variable called VT_API_KEY

### Requiremnts
Python 3.7+

### Install Dependencies
````
% python3 -m pip install -r requirements.txt
````
### Usage
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

### Sample output
````
% python3 /dpool/vcmain/dev/py/vtscan/vtscan.py /tmp/nc.exe
.: Details :.
- md5: 6a6adda21284218fc65eb65d7198af34
- sha1: c5e19c02a9a1362c67ea87c1e049ce9056425788
- sha256: bf01148b2a428bf6edff570c1bbfbf51a342ff7844ceccaf22c0e09347d59a54
- Permalink: https://www.virustotal.com/gui/file/bf01148b2a428bf6edff570c1bbfbf51a342ff7844ceccaf22c0e09347d59a54/detection/f-bf01148b2a428bf6edff570c1bbfbf51a342ff7844ceccaf22c0e09347d59a54-1634433789

.: File :.
- File: nc.exe
- Path: /tmp

.: Virus Total Summary :.
- Detections: 25 out of 65 (Go to VirusTotal for more details)

~
````

### VTScan GUI (new)
![VTScan GUI](https://raw.githubusercontent.com/JavaScriptDude/vtscan/master/VTScan_GUI.png)

By Scanning the QR Code on a mobile device, do a side channel validation to VirusTotal enabling you to bypass potential MITM attacks on VirusTotal data on the target machine's network.


# Alternatives
1. Virus Total official [cli utility](https://github.com/VirusTotal/vt-cli)
