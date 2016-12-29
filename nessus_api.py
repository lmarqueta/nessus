#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import requests
import os
import sys
import yaml
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning


def configure(file="nessus.yaml"):
    if os.path.exists(file):
        with open(file, 'r') as f:
            c = yaml.safe_load(f)
            return c
    else:
        sys.stderr.write("Error: configuration file not found\n")
        sys.exit(1)


def get_url(path):
    url = "https://{}:{}/{}".format(host, port, path)
    return url


def call_api(method, path, data=None):
    url = get_url(path)
    headers = {
        'Content-type': 'application/json',
        'X-ApiKeys': 'accessKey='+access+'; secretKey='+secret
    }
    if method == "get":
        r = requests.get(url, headers=headers, verify=verify)
    elif method == "put":
        r = requests.put(url, headers=headers, data=json.dumps(data), verify=verify)
    else:
        sys.stderr.write("Error: unknown method")
        sys.exit(1)

    if r.status_code == 200:
        return r.json()
    else:
        sys.stderr.write("Error {}\n".format(r.status_code))
        sys.exit(1)


def update_scan(scan_name, filename):
    print 'Updating scan <{}> with file <{}>'.format(scan_name, filename)

    # Find scan. Note that scan names should be unique :(
    # This code will return the first scan found with the given name
    scan_id = None
    targets = []

    r = call_api("get", "scans")
    for s in r['scans']:
        if s['name'] == scan_name:
            scan_id = s['id']
    if scan_id == None:
        sys.stderr.write("Error, scan <{}> not found\n".format(scan_name))
        sys.exit(1)

    # Find filename. We expect to find a file with a host per line
    if os.path.exists(filename):
        with open(filename, 'r') as f:
             targets = f.read().splitlines()
    else:
        sys.stderr.write("Error, file <{}> not found\n".format(filename))
        sys.exit(1)

    text_targets = ','.join(targets)
    data = {'settings': {'enabled': True, 'text_targets': text_targets}}
    path = "scans/{}".format(scan_id)
    r = call_api("put", path, data)
    print "Scan updated"


if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config',
        dest="config_file",
        required = False,
        help="Configuration file")

    # Commands
    subparsers = parser.add_subparsers(dest="command")
    u_parser = subparsers.add_parser("update")
    d_parser = subparsers.add_parser("download")

    # update scan
    u_parser.add_argument("-s", "--scan",
        dest = "scan",
        required = True,
        help = "Scan to be updated")
    u_parser.add_argument("-f", "--filename",
        dest = "filename",
        required = True,
        help = "Filename containing list of targets")

    args = parser.parse_args()
    command = args.command

    # Configuration file
    if args.config_file:
        c = configure(args.config_file)
    else:
        c = configure()
    host   = c['host']['hostname']
    port   = c['host']['port']
    access = c['host']['access']
    secret = c['host']['secret']
    verify = c['host']['verify']

    # Disable SSL warnings: not recommended
    if c['host']['disable_warnings']:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Command: update
    if command == "update":
        update_scan(args.scan, args.filename)
