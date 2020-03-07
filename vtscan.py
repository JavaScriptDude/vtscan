from __future__ import print_function
#########################################
# .: vtscan :.
# Verifies a file using VirusTotal API
# .: Sample :.
# export VT_API_KEY=<virus_total_api_key>
# .: usage :.
# vtscan <path_to_file>
# -or-
# python3 vtscan.py <path_to_file>
# .: deployment :.
# # put vtscan.py in a folder on your machine
# % alias vtscan="python3 <path_to_vtscan_folder>/vtscan.py"
# .: Other :.
# Author: Timothy C. Quinn
# Home: https://github.com/JavaScriptDude/vtscan
# Licence: https://opensource.org/licenses/MIT
# .: Todo :.
# (none)
#########################################

import os, sys, json, hashlib, traceback, pathlib, argparse
from virus_total_apis import PublicApi as VirusTotalPublicApi


def main():

    argp = argparse.ArgumentParser(prog="vtscan")
    argp.add_argument("--verbose", "-v", action='store_true')
    argp.add_argument("--links", "-L", action='store_true')
    argp.add_argument("file", type=str, help="File to scan")

    args = argp.parse_args()

    dump_response : bool = False
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

    vt = VirusTotalPublicApi(API_KEY)

    response = vt.get_file_report(digest_sha256)

    if not response['response_code'] == 200:
        dump_response = True
        warnings.append("Bad general response_code from Virus Total")


    if len(warnings) == 0: # Dig into the results...
        res = response['results']
        if not res['response_code'] == 1:
            dump_response = True
            if res['resource'] == '87b566abab9888ff362058f90818f8dae6cf3e2a67de645e446a2999983a91a2':
                warnings.append("File not found in VirusTotal database. Therefore its safety is unknown.")
                warnings.append("Check if the download source has checksums to verify or Try googling one or all the checksums.")
            else:
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


    if dump_response or args.verbose:
        print(".: Raw Virus Total Response :.\n" + json.dumps(response, sort_keys=False, indent=4) + "\n~\n")

    print("""
.: Details :.
- md5: {0}
- sha1: {1}
- sha256: {2}""".format(digest_md5, digest_sha1, digest_sha256) )

    if got_results:
        print("- Permalink: " + res['permalink'])

    if args.links or not got_results or result_issues > 0:
        print("""
.: Search Links for hand testing :.
- Google MD5: https://www.google.com/search?q=%22{0}%22
- Google SHA1: https://www.google.com/search?q=%22{1}%22
- Bing MD5: https://www.bing.com/search?q=%22{0}%22
- Bing SHA1: https://www.bing.com/search?q=%22{1}%22""".format(digest_md5,digest_sha1))

    print("""
.: File :.
- File: {0}
- Path: {1}""".format(fname, fpath) )


    if got_results:
        print("\n.: Virus Total Summary :.")
        if result_issues == 0:
            print("- Detections: 0 out of {} (100% pass)".format(res['total']))
        else:
            print("- Detections: {} out of {} (Go to VirusTotal for more details)".format(result_issues, res['total']))

    


    if len(warnings) > 0:
        print(".: Warnings :.")
        for i, warning in enumerate(warnings):
            print(" {}) {}".format(i, warning))

    print("~")



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
