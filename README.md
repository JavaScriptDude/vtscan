# vtscan
VirusTotal File Scanner CLI Tool

VirusTotal is a Free service that keeps track of file scan information for any kind of file on the internet. If they don't have the file registered, you can upload the file to have it scanned by dozens of engines to have it analyzed for issues. VirusTotal gives you a way to confirm the safety of a file downloaded quickly without having to install any anti-virus software on your computer. This is very handy for doing ad-hoc virus scans of individual files downloaded off the internet before running them; like program installers, executables and scripts.

### Virus Total API Key
This tool requires that you first get a API Key from Virus Total:
1. Create a free account on [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Once verified, log in -> Click on avatar on top right -> API Key
3. Set the API key to an environment variable called VT_API_KEY

### Requirements
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
  --stdin, -            Read file from stdin (can use '-' also. Eg % curl https://foo.com/some_installer | vtscan - )
  --hash, -m            sha1 or sha256 hash to scan
  ````

### Sample output
````
:~/Downloads$ vtscan drawio-amd64-23.1.5.deb

.: File in :.
  File : drawio-amd64-23.1.5.deb
  Path : /home/timq/Downloads

.: Virus Total :.
  sha1      : 48aaadb049dba1411459d032188d0252b4780727
  sha256    : 29a4a2acacd1388bcd23692b151f34422a94966099cab31ae57ef69a1c01d3a6
  Permalink : https://www.virustotal.com/gui/file/29a4a2acacd1388bcd23692b151f34422a94966099cab31ae57ef69a1c01d3a6/details

.: VirusTotal Details :.
  First Submission : 2024-02-16 19:46:56
  Names            : ['drawio-amd64-23.1.5.deb', '8af81a5d-4f2b-4ce1-aebd-e681e8124f0d', 'draw.io']
  Magic            : Debian binary package (format 2.0), with control.tar.gz, data compression xz
  Type             : file
  Size             : 94,021kb

.: Virus Total Summary :.
   Detections : 0 out of 56 (100% pass)
                                               
   ▄▄▄▄▄▄▄     ▄ ▄    ▄   ▄  ▄ ▄ ▄▄▄ ▄▄▄▄▄▄▄   
   █ ▄▄▄ █ ▀ █▄  ▄█▀ ▀ ▀█▄ ▄ ▄▀█   ▄ █ ▄▄▄ █   
   █ ███ █ ▀ ▀██ ▄▄▄ ▀ ▄▄▀█▀▀▀▀▀█▀▄▀ █ ███ █   
   █▄▄▄▄▄█ █ ▄▀▄▀▄ ▄▀█▀▄▀▄ ▄ █▀▄▀▄ █ █▄▄▄▄▄█   
   ▄▄▄▄▄ ▄▄▄▄▀▄▀▄▄ █▄▄██▀▀ ▀▄██ ▄  █▄ ▄ ▄ ▄    
   █▀▀▄ █▄▀▀▄  ██▄▄ █ ▀ ▄█▀█ ▄▄█▄ ▀█▄██▀▀ ▄▀   
   ▀ ▄▄▄█▄▄█▄▄▄ ▀▄▄█▀▀ █▀▄▀█▄  █▄ ▀   █▀█▄▄    
   ▀▀▀▀▄█▄▄  ▀ ▀▄ █▄▀█ ▄██▀▄▀▀▄▄ ▀▀█▀▀▄█▄▀ ▀   
   ▀  ▄▀█▄▀██▀ ▀▄ █▄▄█  ▀▄  ▄▀▄ ▄▀ ▄▄▀▄ ▄▄▀    
   ▄▄ ██▄▄ ▄▄▀▀█ ▀▄▄ ▄▀█▀ ▀▀▄ ▄▄ ▀▀██▀█▀  ▀▀   
    █▄▀ █▄ ▄ ▀ ▄ ▀▄  ▄▀ █▀█ ▄█▀▀▄  ▀ ▀█▀█▄█▀   
   █▄█ ▀▄▄  ▀█▄▄ ▀▀▀▀▄▄▀█ ▀ █▄▄█ █▀█▀█ █▀  ▀   
    ▀▄█ ▄▄█▄▀▄█ ▄▀ █▄▀█▀▀▀ ▄▄██ ▄  ▄▀▀▄▀▄▄█▄   
   ▄▀█▀ ▄▄▀ █▀▀▀██▄ █▀▀█ █▀▀  ▄█▄▀▀▀▄▀█▀▄▄▄▀   
   █▄▄▀▀ ▄ █▄ ▀▀▀▄▄▄▀▀ ▄▄▄ ▄▄▀ █▄█▀▄  █ ▄▄█▀   
   █ ▀▄ ▀▄▀ ▀  ▀ ▄█▄▄█ ▄▀ ▀▄▄█▄▄▀ ▀▄▀▀ ▀▄▀▀▀   
   █  ▀█ ▄▄  █ ▀▄▀█▄▄▀  ▀▄ ▄▄▄█ ▄█▀▄████▄▄▀▄   
   ▄▄▄▄▄▄▄ █▄█▀█ ▀▄  █▀██ ▀▄▄▄▄█▄▀██ ▄ █ █▄▀   
   █ ▄▄▄ █ ▄▀▀▀▄ ▀█▀ ▄▀ █▀▄▄▄ ▄ ▄█▀█▄▄▄█ ▄▀    
   █ ███ █ █ ▄▄▄ ▀▀▀▄▄▄▀█▀▀ ▀ ▄██ ▀▄▄▄ ▄▀▄▀▀   
   █▄▄▄▄▄█ █▀▄█▄▄█ ▀▄ █▀▀██▄▄█▀ ▄▀▀▀█▄█ ▄▄▀    
                                               
                                               
--- vtscan end ---
````
Note: the QR Code above displays correctly in a terminal window and is scannable.

By Scanning the QR Code on a mobile device, do a side channel validation to VirusTotal enabling you to bypass potential MiTM attacks on VirusTotal data on the target machine's network.


# Alternatives
1. Virus Total official [cli utility](https://github.com/VirusTotal/vt-cli)
