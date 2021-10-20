from __future__ import print_function
#########################################
# .: vtscan :.
# Verifies a file using VirusTotal API
# .: install dependencies :.
# python3 -m pip install -r requirements.txt
# .: Sample :.
# export VT_API_KEY=<virus_total_api_key>
# .: usage :.
# vtscan <path_to_file>
# -or-
# python3 vtscan.py <path_to_file>
# .: deployment :.
# # put vtscan.py in a folder on your computer by hand or using git
# % alias vtscan="python3 <path_to_vtscan_folder>/vtscan.py"
# .: Other :.
# Author: Timothy C. Quinn
# Home: https://github.com/JavaScriptDude/vtscan
# Licence: https://opensource.org/licenses/MIT
# .: Todo :.
# (none)
#########################################

import os, sys, json, hashlib, traceback, pathlib, argparse, subprocess, shutil, qrcode


from virus_total_apis import PublicApi as VirusTotalPublicApi
from PySide2.QtCore import QObject
from PySide2.QtQml import QQmlApplicationEngine
from PySide2.QtWidgets import QApplication

def main():
    argp = argparse.ArgumentParser(prog="vtscan")
    argp.add_argument("--verbose", "-v", action='store_true')
    argp.add_argument("--nogui", "-n", action='store_true')
    argp.add_argument("--links", "-L", action='store_true')
    argp.add_argument("--browser", "-b", type=str, help="Browser to launch for Virus Total Info or other searches")
    argp.add_argument("file", type=str, help="File to scan")

    args = argp.parse_args()

    api_call_failed : bool = False
    got_results : bool = False
    result_issues : int = -1
    warnings : list = []

    # Check for Api key
    if "VT_API_KEY" not in os.environ:
        argp.print_help()
        exit("\nMissing Virus total API Key. Please set VT_API_KEY environment variable!", 1)

    API_KEY=os.environ["VT_API_KEY"]
    if API_KEY.strip() == "":
        argp.print_help()
        exit("\nMissing Virus total API Key. Please set VT_API_KEY environment variable!", 1)

    # Verify that file exists
    if not os.path.isfile(args.file):
        argp.print_help()
        exit("\nPlease specify path to an existing file", 1)

    # Get args.file (first arg)
    fname, fpath = splitPath(args.file)

    # Get sha1 checksum of file
    digest_md5 = getChecksum(args.file, 'md5')
    digest_sha1 = getChecksum(args.file, 'sha1')
    digest_sha256 = getChecksum(args.file, 'sha256')

    # print("digest_sha256 = " + digest_sha256)

    vt = VirusTotalPublicApi(API_KEY)

    response = vt.get_file_report(digest_sha256)


    if 'response_code' in response:
        print("!!response_code in response")

    if not 'response_code' in response:
        api_call_failed = True
        warnings.append("Call to Virus Total API Failed")                    
        if 'error' in response:
            err_msg = response['error']
            if err_msg.find("Max retries exceeded with url") > -1:
                warnings.append("Please check your network connection")                    

    elif not response['response_code'] == 200:
        api_call_failed = True
        warnings.append("Bad general response_code from Virus Total")                    

    if not api_call_failed: # Dig into the results...
        res = response['results']

        if not res['response_code'] == 1:
            if res['verbose_msg'] == 'The requested resource is not among the finished, queued or pending scans':
                warnings.append("File not found in VirusTotal database. Therefore its safety is unknown.")
                warnings.append("Alternate verifications may be required")
            else:
                api_call_failed = True
                warnings.append("Bad result response_code from virus total: {}")

        # print("Raw virus total results: {}".format(json.dumps(res, sort_keys=False, indent=4)), 1)
        
        if len(warnings) == 0:
            # Lets be paranoid and verify the checksums found
            if not res['md5'] == digest_md5:
                warnings.append("MD5 Checksums do not match:\n -    Original: {}\n - Virus Total: {}".format(digest_md5, res['md5']))
            if not res['sha1'] == digest_sha1:
                warnings.append("SHA1 Checksums do not match:\n -    Original: {}\n - Virus Total: {}".format(digest_sha1, res['sha1']))
            if not res['sha256'] == digest_sha256:
                warnings.append("SHA256 Checksums do not match:\n -    Original: {}\n - Virus Total: {}".format(digest_sha256, res['sha256']))
            
            got_results = True
            result_issues = res['positives']


    if api_call_failed or args.verbose:
        print(".: Raw Virus Total Response :.\n" + json.dumps(response, sort_keys=False, indent=4) + "\n")


    print("""
.: Details :.
- md5: {0}
- sha1: {1}
- sha256: {2}""".format(digest_md5, digest_sha1, digest_sha256) )

    if got_results:
        print("- Permalink: " + res['permalink'])

        if not args.nogui:
            # Encoding data using make() function
            img = qrcode.make(res['permalink'])
            
            # Saving as an image file
            # TODO - Save as tempfile
            img.save('/tmp/_QRCode.png')


    print("\n.: File :.\n- File: {0}\n- Path: {1}".format(fname, fpath) )


    if got_results:
        print("\n.: Virus Total Summary :.")
        if result_issues == 0:
            print("- Detections: 0 out of {} (100% pass)".format(res['total']))
        else:
            print("- Detections: {} out of {} (Go to VirusTotal for more details)".format(result_issues, res['total']))


    if len(warnings) > 0:
        print("\n.: Warnings :.")
        for warning in warnings:
            print("- {}".format(warning))

    

    if not api_call_failed and args.browser:
        exe = shutil.which(args.browser)
        if exe is None:
            print("\n  Note: Browser not launched executable not found: " + args.browser)
        else:
            if not got_results:
                urls = search_urls
                print("""
  Signature not found in Virus Total so will search in google
  and bing for hash signatures. If no results are found,
  it is strongly recommended to take care with this file.""")
            else:
                print("\n  Note: Launching Virus Total in " + args.browser)
                urls = [res['permalink']]

            for url in urls:
                cmd = [exe, url]
                subprocess.Popen(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    if not api_call_failed and not got_results:
                print("""
  If this is an installer, executable, or other file that does not contain
  personal information (for example not a zip archive of personal files),
  you may want to consider uploading to VirusTotal to do a deep scan at:
 - https://www.virustotal.com/gui/home/upload""")


    if not args.nogui:
        app = QApplication([])
        engine = QQmlApplicationEngine()

        _constants = {
            'Labels': {
                'Indent': 140
            }
        }
        engine.rootContext().setContextProperty("C", _constants)
        qml = None
        with open('/dpool/vcmain/dev/py/vtscan/vtscan.qml') as f:
            lines = [ line.strip('\n') for line in list(f) ]
            qml = str.encode('\n'.join(lines))

        
        engine.loadData(qml)
        root_obj = engine.rootObjects()
        if not len(root_obj) == 1:
            raise Exception("Issue Parsing QML. Exiting Program")
        win = root_obj[0]

        def _setText(name, value):
            o = win.findChild(QObject, name)
            o.setProperty("text", value)


        _setText("txtFile", fname)
        _setText("txtPath", fpath)
        _setText("txtMd5", digest_md5)
        _setText("txtSha1", digest_sha1)
        _setText("txtSha256", digest_sha256)
        if got_results:
            _setText("txtLink", f"<a href='{res['permalink']}''>VirusTotal.com</a>")
            _setText("txtRes", digest_sha256)
            if result_issues == 0:
                _setText("txtRes", "Detections: 0 out of {} (100% pass)".format(res['total']))
            else:
                _setText("txtRes", "Detections: {} out of {} (Go to VirusTotal for more details)".format(result_issues, res['total']))
        else:
            _setText("txtLink", 'n/a')
            _setText("txtRes", "Not Registered in VirusTotal")

        o = win.findChild(QObject, "qrcode")
        o.setProperty('source', 'file:///tmp/_QRCode.png')
        


        app.exec_()




def getChecksum(path, csumtype):
    if csumtype == 'md5':
        h  = hashlib.md5()
    elif csumtype == 'sha1':
        h  = hashlib.sha1()
    elif csumtype == 'sha256':
        h  = hashlib.sha256()
    else:
        raise Exception("Unexpected csumtype: {}".format(csumtype))
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(path, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


def exit(s, exitCode=1):
    if not s is None:
        print(s)
    print('~')
    sys.stdout.flush()
    sys.stderr.flush()
    sys.exit(exitCode)


def splitPath(s):
    f = os.path.basename(s)
    p = s[:-(len(f))-1]
    p = toPosixPath(getAbsPath(p))
    return f, p


def toPosixPath(s:str, strip_slash:bool=False, ensure_slash:bool=False):
    s = s.strip().replace('\\', '/')
    if strip_slash and s[-1:] == '/':
        return s[:-1]
    if ensure_slash and not s[-1:] == '/':
        return '%s/' % s
    return s


def getAbsPath(s:str):
    return os.path.abspath( pathlib.Path(s).expanduser() )




if __name__ == '__main__':
    iExit = 0
    try:
        main()
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        aTB = traceback.format_tb(exc_traceback)
        exit("Program Exception:\nStack:\n{}\n Error: {} - {}".format('\n'.join(aTB), exc_type.__name__, exc_value), exitCode=1)
    sys.exit(iExit)
