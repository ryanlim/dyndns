#!/usr/bin/env python3

import urllib.request, urllib.error, urllib.parse
import json
import subprocess
import sys
import time
import os

import fcntl
PID_FILE = f"/tmp/nsupdate-{os.environ['USER']}.pid"
fp = open(PID_FILE, 'w')
try:
    fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
except IOError:
    # another instance is running
    print("Another instance is running.")
    sys.exit(1)


try:
    with open('config.json', 'r') as f:
        config = json.load(f)
except Exception:
    print("config.json not found.")
    sys.exit(1)

min_config=('zone', 'zone_master', 'host', 'keyfile')
for c in min_config:
    if c not in list(config.keys()):
        print(("Missing %s option in the config file." % (c,)))
        sys.exit(1)

if config.get('debug', False):
    import pprint
    print("Config:")
    pprint.pprint(config, indent=4)

zone = config['zone']
host = config['host']

def getPublicIP(addr_type='4'):
    if addr_type == '4':
        endpoint = 'https://ip.limau.net?format=json'
    elif addr_type == '6':
        endpoint = 'https://ip6.limau.net?format=json'
    else:
        return None

    req = urllib.request.Request(endpoint)
    req.add_header('User-agent', 'nsupdate')
    try:
        res = urllib.request.urlopen(req)
    except urllib.error.URLError as e:
        #print "Cannot obtain public IP v%s address: %s" % (addr_type, e)
        return None

    if res == None:
        #print "Cannot obtain public IP v%s address: %s" % (addr_type, e)
        return None

    res_json = json.loads(res.read())
    ip_address = res_json['ip_candidates'][0]['ip']
    return ip_address

# This is a janky way to get the IP address.
# At some point we should get this via a proper method
def getBonjourIP():
    command = """/sbin/ifconfig utun0 | grep inet6 | grep "scopeid" | grep "prefixlen 64" | awk '{ print $2 }' | cut -f 1 -d %"""
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    ip_bonjour = process.communicate()[0].rstrip().decode('utf-8')
    return ip_bonjour

# This is a janky way to get the IP address.
# At some point we should get this via a proper method
def getLocalIP():
    command = (
        "/usr/sbin/ipconfig getifaddr "
        "$(/usr/sbin/netstat -nr | grep default | "
        "grep UGSc | awk '{ print $NF }')"
    )
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    ip = process.communicate()[0].rstrip().decode('utf-8')
    return ip


ip4_address = getPublicIP('4')
ip6_address = getPublicIP('6')

def setOrUpdate(host, ttl, rtype, data):
    ret = []
    ret.append(f"update delete {host} {rtype}")
    if data is not None:
        ret.append(f"update add {host} {ttl} {rtype} {data}")
    ret.append("send")
    return ret

zone_update_commands = []
zone_update_commands.append(f"zone {zone}")
zone_update_commands.append(f"server {config['zone_master']}")

ts_now = time.strftime("%Y-%m-%d %H:%M:%S %z")

zone_update_commands += setOrUpdate(
    f"{host}.{zone}",
    60,
    "TXT",
    f"\"Updated: {ts_now}\""
)

zone_update_commands += setOrUpdate(
    f"{host}.{zone}",
    60,
    "A",
    ip4_address
)

zone_update_commands += setOrUpdate(
    f"{host}.{zone}",
    60,
    "AAAA",
    ip6_address
)

zone_update_commands.append(f"update delete {host}-local.{zone} A")
if config.get('has_local', False):
    ip_local = getLocalIP()
    if ip_local != None and ip_local != "":
        zone_update_commands.append(
            f"update add {host}-local.{zone} 60 A {ip_local}"
        )
zone_update_commands.append("send")

zone_update_commands.append(f"update delete {host}-wa.{zone} AAAA")
if config.get('has_bonjour', False):
    ip_bonjour = getBonjourIP()
    if ip_bonjour != None and ip_bonjour != "":
        zone_update_commands.append(
            f"update add {host}-wa.{zone} 60 AAAA {ip_bonjour}"
        )
zone_update_commands.append("send")

if config.get('alt_names'):
    alt_names = config.get('alt_names', [])

    for alt in alt_names:
        zone_update_commands += setOrUpdate(
            f"{alt}-txt.{zone}",
            60,
            "TXT",
            f"\"Updated: {ts_now}\""
        )

        zone_update_commands += setOrUpdate(
            f"{alt}.{zone}",
            60,
            "CNAME",
            f"{host}.{zone}"
        )


zone_update = "\n".join(zone_update_commands)

if config.get('debug', False):
    print("Sending nsupdate data:")
    print(zone_update)

# This is a janky way to use nsupdate
# At some point we should get this via a proper method.

command = ["/usr/bin/nsupdate", "-k", config['keyfile']]
process = subprocess.Popen(
    command,
    stdout=subprocess.PIPE,
    stdin=subprocess.PIPE,
    stderr=subprocess.PIPE
)
process.communicate(input=zone_update.encode())

try:
    fcntl.lockf(fp, fcntl.LOCK_UN)
except IOError:
    # another instance is running
    print("Failed to unlock.")
    sys.exit(1)

os.unlink(PID_FILE)
