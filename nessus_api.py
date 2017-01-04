#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import requests
import os
import sys
import yaml
import json
import logging
import sqlite3


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
    print("Scan updated")


def list_all_folders():
    r = call_api("get", "folders")
    if not args.quiet:
        print(" fid Folder name")
        print("==== =============================================")
    for t in r['folders']:
        if not quiet:
            print("{:>4} {}".format(t['id'], t['name']))


def list_all_scans():
    r = call_api("get", "scans")
    if not args.quiet:
        print(" fid  sid Scan name")
        print("==== ==== =============================================")
    for t in r['scans']:
        if not quiet:
            print("{:>4} {:>4} {}".format(t['folder_id'], t['id'], t['name']))


def list_folder(folder_id):
    r = call_api("get", "scans")
    for s in r['scans']:
        if s['folder_id'] == int(folder_id):
            if not quiet:
                # if quiet, this function is useless :)
                print("{:>4} {}".format(s['id'], s['name']))


def list_scan(scan_id):
    r = call_api("get", "scans/{}".format(scan_id))

    if not quiet:
        name = r['info']['name']
        if 'hostcount' in r['info']:
            c = r['info']['hostcount']
        else:
            c = 0
        print ("Scan:{}:{}:{}".format(scan_id,name, c))
        print(" Id  C  H  M  L Hostname                        ")
        print("=== == == == == ================================")

    if 'hosts' not in r:
        return

    for d in r['hosts']:
        hid = d['host_id']
        name = d['hostname']
        c = d['critical']
        h = d['high']
        m = d['medium']
        l = d['low']
        if not quiet:
            print("{:>3} {:>2} {:>2} {:>2} {:>2} {}".format(hid,
                c, h, m, l, name))

        if updatedb:
            insert_host(hid, name, scan_id)


def severity_name(n):
    if n == 0:
        return 'INFO'
    elif n == 1:
        return 'LOW'
    elif n == 2:
        return 'MEDIUM'
    elif n == 3:
        return 'HIGH'
    elif n == 4:
        return 'CRITICAL'
    else:
        return 'UNKNOWN'


def host_details(scan_id, host_id):
    r = call_api("get", "scans/{}/hosts/{}".format(scan_id, host_id))
    fqdn = ip = netbios = os = mac = ""
    if 'host-fqdn' in r['info']:
        fqdn = r['info']['host-fqdn']
    if 'host-ip' in r['info']:
        ip = r['info']['host-ip']
    if 'netbios-name' in r['info']:
        netbios = r['info']['netbios-name']
    if 'operating-system' in r['info']:
        os = r['info']['operating-system']
    if 'mac' in r['info']:
        mac = r['info']['mac-address']
    os_data = [fqdn, ip, netbios, os, mac]
    if updatedb:
        insert_os(os_data)

    if not quiet:
        print("Host: {}".format(fqdn))
        print("IP address: {}".format(ip))
        print("Netbios: {}".format(netbios))
        print("Operating system: {}".format(os))
        print("MAC address: {}".format(mac))

    for d in r['vulnerabilities']:
        severity = d['severity']
        name = d['plugin_name']
        plugin = d['plugin_id']
        if not quiet:
            print("{:8} {:>5} {}".format(severity_name(severity), plugin, name))

        vuln_data = [scan_id, host_id, severity, name, plugin]
        if updatedb:
            insert_vuln(vuln_data)


def insert_host(id, hostname, scan_id):
    try:
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()
        sql = "insert into hosts \
            (host_id, hostname, scan_id) \
            values (?, ?, ?)"
        c.execute(sql, [id, hostname, scan_id])
        conn.commit()
        conn.close()
        return True
    except:
        raise
        return False

def insert_vuln(data):
    try:
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()
        sql = "insert into vulnerabilities \
            (scan_id, host_id, severity, name, plugin) \
            values (?, ?, ?, ?, ?)"
        c.execute(sql, data)
        conn.commit()
        conn.close()
        return True
    except:
        raise
        return False


def insert_os(data):
    try:
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()
        sql = "insert into os \
            (fqdn, ip, netbios, os, mac) \
            values (?, ?, ?, ?, ?)"
        c.execute(sql, data)
        conn.commit()
        conn.close()
        return True
    except:
        raise
        return False


if __name__ == "__main__":
    # Keep warnings out of console
    logging.captureWarnings(True)

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config',
        dest="config_file",
        required = False,
        help="Configuration file")
    parser.add_argument('-q', '--quiet',
        dest="quiet",
        required = False,
        action="store_true",
        help="Do not output to console")
    parser.add_argument('-u', '--updatedb',
        dest="updatedb",
        required = False,
        action="store_true",
        help="Updates database")

    # Commands
    subparsers = parser.add_subparsers(dest="command")
    u_parser = subparsers.add_parser("us")
    las_parser = subparsers.add_parser("las")
    laf_parser = subparsers.add_parser("laf")
    lf_parser = subparsers.add_parser("lf")
    ls_parser = subparsers.add_parser("ls")
    hd_parser = subparsers.add_parser("hd")

    # update scan
    u_parser.add_argument("-s", "--scan",
        dest = "scan",
        required = True,
        help = "Scan to be updated")
    u_parser.add_argument("-f", "--filename",
        dest = "filename",
        required = True,
        help = "Filename containing list of targets")

    # list folder
    lf_parser.add_argument("-f", "--folder",
        dest = "folder_id",
        required = True,
        help = "Folder ID")

    # list scan
    ls_parser.add_argument("-s", "--scan",
        dest = "scan_id",
        required = True,
        help = "Scan ID")

    # host details
    hd_parser.add_argument("-s", "--scan",
        dest = "scan_id",
        required = True,
        help = "Scan ID")
    hd_parser.add_argument("-H", "--host",
        dest = "host_id",
        required = True,
        help = "Host ID")

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
    dbfile = c['db']['path']

    # console output
    quiet = args.quiet
    updatedb = args.updatedb

    # Command: update
    if command == "us":
        update_scan(args.scan, args.filename)

    if command == "laf":
        list_all_folders()

    if command == "las":
        list_all_scans()

    if command == "lf":
        list_folder(args.folder_id)

    if command == "ls":
        list_scan(args.scan_id)

    if command == "hd":
        host_details(args.scan_id, args.host_id)
