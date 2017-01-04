# nessus
Nessus helper scripts

At this moment there are a few options:

```
usage: nessus_api.py [-h] [-c CONFIG_FILE] [-q] [-u] {us,las,laf,lf,ls,hd} ...
```

There are a couple of options before the *command*:

* -c: configuration file. Defaults to `nessus.yaml`
* -q: avoids most console output
* -d: inserts output on a SQLite database

And then the commands:

## Update scan

```
usage: nessus_api.py us [-h] -s SCAN -f FILENAME

optional arguments:
  -h, --help            show this help message and exit
  -s SCAN, --scan SCAN  Scan to be updated
  -f FILENAME, --filename FILENAME
                        Filename containing list of targets
```

Updates a existing scan with a list of target hosts. Hosts are stored in a text file, one hosts per line. For example:

```
host-1.domain
host-2.domain
host-3.another.domain
``

## List all folders

Lists all folders (yes, you guessed)

```
./nessus_api.py laf -h
usage: nessus_api.py laf [-h]

optional arguments:
  -h, --help  show this help message and exit
```

Example:

```
./nessus_api.py laf
 fid Folder name
==== =============================================
   2 Trash
   3 My Scans
   4 Test scan
```

## List all scans

```
usage: nessus_api.py las [-h]

optional arguments:
  -h, --help  show this help message and exit
```

Just does what it says. Prints folder_id, scan_id and scan name. Useful as output to other commands.

Example:

```
python nessus_api.py -c nessus.yaml

 fid  sid Scan name
==== ==== =============================================
   3  877 Development desktops
   4  888 Production web servers
 543  893 Database servers

```

## List folder

```
usage: nessus_api.py lf [-h] -f FOLDER_ID

optional arguments:
  -h, --help            show this help message and exit
  -f FOLDER_ID, --folder FOLDER_ID
                        Folder ID
```

List scan names for a particular folder. Example:

```
python nessus_api.py -c nessus.yaml lf --folder 127
 441 Internal Windows servers
 413 Pre-production database servers
 415 Whatever
```

## List scan

```
usage: nessus_api.py ls [-h] -s SCAN_ID

optional arguments:
  -h, --help            show this help message and exit
  -s SCAN_ID, --scan SCAN_ID
                        Scan ID
```

Shows a scan summary, including hostnames and the number of vulnerabilities per host. Example:

```
python nessus_api.py ls --scan 667
Scan name: test scan
Host count: 4

 Id  C  H  M  L Hostname                        
=== == == == == ================================
  5  0  0  5  8 hostname1.domain
  4  0  0  5  8 hostname2.domain
  2  0  0 11 18 pre-hostname3.domain
  3  6 11 34 45 forgotten.server.domain
```

The columns left indicate:

* id: host id
* C: number of critical vulnerabilities
* H: high vulnerabilites
* M: medium
* L: low

Now go and patch `forgotten.server.domain` please!

## Host details

Shows details for a particular host in a particular scan:

```
usage: nessus_api.py hd [-h] -s SCAN_ID -H HOST_ID

optional arguments:
  -h, --help            show this help message and exit
  -s SCAN_ID, --scan SCAN_ID
                        Scan ID
  -H HOST_ID, --host HOST_ID
                        Host ID

```

Example:

```
python nessus_api.py hd --scan 77 --host 6 | grep -v ^INFO
Host: pc.local
IP address: 192.168.1.1
Netbios: PC
Operating system: Microsoft Windows 7
MAC address: 

MEDIUM   57608 SMB Signing Disabled
MEDIUM   26919 Microsoft Windows SMB Guest Account Local User Access
```
