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
usage: vtscan [-h] [--verbose] [--stdin] [--gui] [--links] [--hash] [--browser BROWSER] file

positional arguments:
  file                  File to scan or hash (see --hash))

options:
  -h, --help            show this help message and exit
  --verbose, -v
  --stdin, -            Read file from stdin (can use '-' also. Eg % echo foo.txt | vtscan -)
  --gui, -g             Launch GUI. Default is CLI
  --links, -L           Launch links in browser
  --hash, -m            sha1 or sha256 hash to scan
  --browser BROWSER, -b BROWSER
                        Browser to launch for Virus Total Info or other searches
  ````

### Sample output
````
% vtscan ~/Downloads/WinSCP-6.1.2-Setup.exe

.: Virus Total :.
  sha1      : fe8cd9dce3f82e76f5a5651c60c72e638f826ade
  sha256    : 36cc31f0ab65b745f25c7e785df9e72d1c8919d35a1d7bd4ce8050c8c068b13c
  Permalink : https://www.virustotal.com/gui/file/36cc31f0ab65b745f25c7e785df9e72d1c8919d35a1d7bd4ce8050c8c068b13c/details

.: File :.
  File : WinSCP-6.1.2-Setup.exe
- Path: /home/tquinn/Downloads

.: Details :.
  Creation      : 2023-02-15 14:54:16
  Names         : ['WinSCP-6.1.2-Setup.exe', 'target.exe (copy)', 'WinSCP-6.1.2-Setup (1).exe', 'target.exe', 'ParzaImage.exe']
  Description   : Setup for WinSCP 6.1.2 (SFTP, FTP, WebDAV and SCP client)
  Version       : 6.1.2
  Original Name : WinSCP-6.1.2-Setup.exe
  Comments      : This installation was built with Inno Setup.
  Magic         : PE32 executable (GUI) Intel 80386, for MS Windows
  Type          : file
  Size          : 10,871kb

.: Virus Total Summary :.
   Detections : 0 out of 72 (100% pass)
~
````

### Scan Installer Scripts
Several installer tools require you to curl a URL on the internet and then pipe it to bash or another engine for evaluation. This kind of feels unsafe and its best to pipe to a file and then read the file.
With vtscan, you can pipe the output and do a scan in real time:
```
% curl -sSL https://install.python-poetry.org | vtscan -

.: Virus Total :.
  sha1      : 83928e644bb08a23a999fd9041b282890430be30
  sha256    : 66db5477a597b6176202ef77792076057ce50d2c5a2d2d2978c63e1f144d7b95
  Permalink : https://www.virustotal.com/gui/file/66db5477a597b6176202ef77792076057ce50d2c5a2d2d2978c63e1f144d7b95/details

.: Stdin :.
  sha256 : 66db5477a597b6176202ef77792076057ce50d2c5a2d2d2978c63e1f144d7b95

.: Details :.
  First Submission : 2023-05-23 07:40:55
  Names            : ['fucktasting.py', 'poetry.py', 'install.python-poetry.org.sh', 'install_poetry.py', 'uninstall_poetry.py']
  Magic            : Python script, ASCII text executable
  Type             : file
  Size             : 27kb

.: Virus Total Summary :.
   Detections : 0 out of 61 (100% pass)
```
This will give you more confidence on the file before running without having to go throught the script line by line.


### VTScan GUI (new)
![VTScan GUI](https://raw.githubusercontent.com/JavaScriptDude/vtscan/master/VTScan_GUI.png)

By Scanning the QR Code on a mobile device, do a side channel validation to VirusTotal enabling you to bypass potential MITM attacks on VirusTotal data on the target machine's network.


# Alternatives
1. Virus Total official [cli utility](https://github.com/VirusTotal/vt-cli)
