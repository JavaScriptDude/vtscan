from __future__ import print_function
'''
 vtscan - VirusTotal Scanner
 Verifies a file using VirusTotal API
 Shows virus total results and includes a QR code
 for easy side channel validation of results

 .: Get free Virus Total API Key :.
 https://developers.virustotal.com/reference/getting-started

 .: Store local copy of API Key in Env vars :.
 export VT_API_KEY=<virus_total_api_key>

 .: install dependency :.
 python3 -m pip install vt-py

 .: Sample :.
 python3 vtscan.py <path_to_file>

 .: deployment :.
 Download vtscan.py to a folder on your system
 % alias vtscan="python3 <path_to_vtscan_folder>/vtscan.py"
 .: Other :.
 Author: Timothy C. Quinn
 Home: https://github.com/JavaScriptDude/vtscan
 Licence: https://opensource.org/licenses/MIT
'''

import os
import sys
import hashlib
import traceback
import pathlib
import argparse
import vt
import qrcode

def main():
    # Hack to handle naked '-' argument
    bStdIn:bool=False
    bFile:bool=False
    for i, arg in enumerate(sys.argv):
        if sys.argv[i] == '-':
            sys.argv[i] = '--stdin'
            bStdIn = True

    argp = argparse.ArgumentParser(prog="vtscan")
    argp.add_argument("--verbose", "-v", action='store_true')
    argp.add_argument("--stdin", "-", action='store_true', help="Read file from stdin (can use '-' also. Eg %% curl https://foo.com/some_installer | vtscan - )")
    argp.add_argument("--hash", "-m", action='store_true', help="sha1 or sha256 hash to scan")
    if not bStdIn:
        argp.add_argument("file", type=str, help="File to scan or hash (see --hash))")

    args = argp.parse_args()

    if bStdIn:
        if args.hash:
            raise Exception("Cannot use --hash with stdin")
    else:
        if args.hash:
            args.hash = args.file
        

    api_call_failed : bool = False
    got_results : bool = False
    warnings : list = []


    # Check for Api key
    if "VT_API_KEY" not in os.environ:
        argp.print_help()
        exit("\nMissing Virus total API Key. Please set VT_API_KEY environment variable!", 1)

    API_KEY=os.environ["VT_API_KEY"]
    if API_KEY.strip() == "":
        argp.print_help()
        exit("\nMissing Virus total API Key. Please set VT_API_KEY environment variable!", 1)

    if args.stdin:
        sb = []
        for line in sys.stdin:
            sb.append(line)
        _stdin = "".join(sb)
        _stdin_bytes = _stdin.encode('utf-8')   

        digest_md5 = hashlib.md5(_stdin_bytes).hexdigest()
        digest_sha1 = hashlib.sha1(_stdin_bytes).hexdigest()
        digest_sha256 = hashlib.sha256(_stdin_bytes).hexdigest()

        fname = "(stdin)"
        fpath = "-"

    elif args.hash:
        digest_md5 = "-"
        digest_sha1 = "-"
        digest_sha256 = "-"
        fname = args.hash
        fpath = "-"

    else:
        bFile = True
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

    _verb:str
    if bFile:
        _verb = f"File: {args.file}"
    elif args.stdin:
        _verb = f"Stdin (sha256 hash: {digest_sha256}))"
    else:
        _verb = f"Hash: {args.hash}"
        
    

    with vt.Client(API_KEY) as client:
        if args.hash:
            _hash = args.hash
        else:
            _hash = digest_sha256


        try:
            res  = client.get_object(f"/files/{_hash}")
        except vt.APIError as ae:
            if ae.code == 'NotFoundError':
                warnings.append(f"{_verb} not found in VirusTotal database. Therefore its safety is unknown.")
                warnings.append("Alternate verifications may be required")
            else:
                warnings.append(f"{_verb} - call failed: {ae}")

        if len(warnings) == 0:
            if bFile:
                # Lets be paranoid and verify the checksums found
                if not res.md5 == digest_md5:
                    warnings.append("MD5 Checksums do not match:\n -    Original: {}\n - Virus Total: {}".format(digest_md5, res.sha256))
                if not res.sha1 == digest_sha1:
                    warnings.append("SHA1 Checksums do not match:\n -    Original: {}\n - Virus Total: {}".format(digest_sha1, res.sha256))
                if not res.sha256 == digest_sha256:
                    warnings.append("SHA256 Checksums do not match:\n -    Original: {}\n - Virus Total: {}".format(digest_sha256, res.sha256))
            else:
                digest_md5 = res.md5
                digest_sha1 = res.sha1
                digest_sha256 = res.sha256

            
            got_results = True


    if bFile:
        print(f"\n.: File in :.\n  File : {fname}\n  Path : {fpath}")

    print(f"""
.: Virus Total :.
  sha1      : {digest_sha1}
  sha256    : {digest_sha256}""")
  
    
    permalink:str = None
    qr:qrcode.QRCode = None
    if got_results:
        permalink = f"https://www.virustotal.com/gui/file/{digest_sha256}/details"
        print(f"  Permalink : {permalink}")


        qr = qrcode.QRCode(
            version=1,  # Controls the size of the QR Code (1 is the smallest)
            error_correction=qrcode.constants.ERROR_CORRECT_L,  # Error correction level
            box_size=10,  # Size of each box in the QR code grid
            border=3,  
        )

        # Add data to the QR Code
        qr.add_data(permalink)
        qr.make(fit=True)
       

    elif args.stdin:
        print(f"\n.: Stdin :.\n  sha256 : {digest_sha256}")

    else:
        print(f"\n.: Hash :.\n  Hash arg : {args.hash}")

    total:int=None
    if got_results:
        harmless = res.last_analysis_stats['harmless']
        suspicious = res.last_analysis_stats['suspicious']
        malicious = res.last_analysis_stats['malicious']
        undetected = res.last_analysis_stats['undetected']
        detected = malicious + suspicious
        total = harmless + suspicious + malicious + undetected
        
        print("\n.: VirusTotal Details :.")
        items = []
        
        if hasattr(res, 'creation_date'):
            items.append( ("Creation", res.creation_date) )
        else:
            if hasattr(res, 'first_submission_date'):
                items.append( ("First Submission", res.first_submission_date) )

        if hasattr(res, 'dot_net_assembly'):
            asy = res.dot_net_assembly
            items.append( (".Net Name", getattr(asy, 'assembly_name', '-')) )
            items.append( (".Net CLR Ver", getattr(asy, 'clr_version', '-')) )

        else:
            items.append( ("Names", res.names[:5]) )

            
        if hasattr(res, 'signature_info'):
            sig = res.signature_info
            items.append( ("Description", getattr(sig, 'description', '-')) )
            items.append( ("Version", getattr(sig, 'file version', '-')) )
            if not hasattr(res, 'dot_net_assembly'):
                items.append( ("Original Name", getattr(sig, 'original name', '-')) )
            items.append( ("Comments", getattr(sig, 'comments', '-')) )

        items.append( ("Magic", res.magic) )

        items.append( ("Type", res.type) )
        items.append( ("Size", f"{int(res.size/1024):,}kb") )

        _print_items(items)
        

        print("\n.: Virus Total Summary :.")
        if detected == 0:
            print("   Detections : 0 out of {} (100% pass)".format(total))
        else:
            print("   Detections : suspicious: {0} and malicious {1} out of {2} (Go to VirusTotal for more details)".format(suspicious, malicious, total))


    if len(warnings) > 0:
        print("\n.: Warnings :.")
        for warning in warnings:
            print("- {}".format(warning))


    if not api_call_failed and not got_results:
        print("""
  If this is an installer, executable, or other file that does not contain
  personal information (for example not a zip archive of personal files),
  you may want to consider uploading to VirusTotal to do a deep scan at:
 - https://www.virustotal.com/gui/home/upload""")


    if got_results:
        # Generate the QR Code as ASCII art and print to terminal
        qr.print_ascii()
        
    print('--- vtscan end ---')




class VTData():
    def __init__(self):
        pass


def _print_items(items):
    iMax:int = 0
    for k, v in items:
        if len(k) > iMax:
            iMax = len(k)
    for k, v in items:
        print("  {0:{1}}: {2}".format(k, iMax+1, v))
        


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

def noop(*args, **kwargs):
    pass

if __name__ == '__main__':
    iExit = 0
    try:
        main()
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        aTB = traceback.format_tb(exc_traceback)
        exit("Program Exception:\nStack:\n{}\n Error: {} - {}".format('\n'.join(aTB), exc_type.__name__, exc_value), exitCode=1)
    sys.exit(iExit)
