#!/usr/bin/env python3

import urllib.request, urllib.error, urllib.parse
import json
import subprocess
import sys
from datetime import datetime, timezone
import os
import pprint
import fcntl
import argparse
import copy

import dns.tsigkeyring
import dns.update
import dns.query
import dns.resolver
import dns.inet

PID_FILE = f"/tmp/nsupdate-{os.environ['USER']}.pid"

URLLIB_TIMEOUT = 10


def getPublicIP(addr_type='4', timeout=URLLIB_TIMEOUT):
    if addr_type == '4':
        endpoint = 'https://ip.limau.net?format=json'
    elif addr_type == '6':
        endpoint = 'https://ip6.limau.net?format=json'
    else:
        return None

    req = urllib.request.Request(endpoint)
    req.add_header('User-agent', 'nsupdate')
    try:
        res = urllib.request.urlopen(req, None, timeout)
    except urllib.error.URLError as e:
        #print "Cannot obtain public IP v%s address: %s" % (addr_type, e)
        return None
    except Exception as e:
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


def getConfig(config_path):
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except Exception:
        print(f"{config_path} not found or invalid json file.")
        sys.exit(1)
    
    min_config=('zone', 'zone_master', 'host', 'tsigkeyring')
    for c in min_config:
        if c not in list(config.keys()):
            print(("Missing %s option in the config file." % (c,)))
            sys.exit(1)
        if c == "tsigkeyring":
            tsigkeyring_keys = ('name', 'secret', 'keyalgorithm')
            for c_ in tsigkeyring_keys:
                if c_ not in list(config[c].keys()):
                    print(("Missing %s option in the config file (tsigkeyring section)." % (c_,)))
                    sys.exit(1)

    return config


if __name__ == "__main__":
    fp = open(PID_FILE, 'w')
    try:
        fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        # another instance is running
        print("Another instance is running.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        prog='nsupdate',
        description='Updates a rfc2136 dynamic DNS record.'
    )
    parser.add_argument('config_path',
                        help='Path to config.json file.')

    args = parser.parse_args()
    config_path = args.config_path
    config = getConfig(config_path)
    
    if config.get('debug', False):
        print("Config:")
        config_ = copy.deepcopy(config)
        if config_.get('tsigkeyring'):
            if config['tsigkeyring'].get('secret', None):
                config_['tsigkeyring']['secret'] = "redacted"

        pprint.pprint(config_, indent=4)
    
    zone = config.get('zone')
    host = config.get('host')
    tsigkeyring = config.get('tsigkeyring', {})
    
    ip4_address = getPublicIP('4', config.get('urllib_timeout', URLLIB_TIMEOUT))
    print(f"IPv4: {ip4_address}")
    ip6_address = getPublicIP('6', config.get('urllib_timeout', URLLIB_TIMEOUT))
    print(f"IPv6: {ip6_address}")

    ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %z")

    keyring = dns.tsigkeyring.from_text({
        tsigkeyring["name"] : tsigkeyring["secret"]
    })

    keyalgorithm = dns.tsig.default_algorithm
    if tsigkeyring["keyalgorithm"] == "hmac-sha256":
        keyalgorithm = dns.tsig.HMAC_SHA256
    elif tsigkeyring["keyalgorithm"] == "hmac-sha512":
        keyalgorithm = dns.tsig.HMAC_SHA512
    elif tsigkeyring["keyalgorithm"] == "hmac-md5":
        keyalgorithm = dns.tsig.HMAC_MD5
    
    updater = dns.update.UpdateMessage(zone,
                                       keyring=keyring,
                                       keyname=tsigkeyring["name"],
                                       keyalgorithm=keyalgorithm)

    zone_master = ""
    if dns.inet.is_address(config['zone_master']):
        zone_master = config['zone_master']
    else:
        zone_master = str(dns.resolver.resolve(config['zone_master'], 'A')[0])

    updater.delete(host, "TXT")
    updater.add(host, 60, "TXT", f"\"Updated on: {ts_now}\"")

    updater.delete(host, "A")
    if ip4_address:
        updater.add(host, 60, "A", ip4_address)

    updater.delete(host, "AAAA")
    if ip6_address:
        updater.add(host, 60, "AAAA", ip6_address)

    updater.delete(f"{host}-local", "A")
    if config.get('has_local', False):
        ip_local = getLocalIP()
        if ip_local != None and ip_local != "":
            updater.add(f"{host}-local", 60, "A", ip_local)

    updater.delete(f"{host}-wa", "AAAA")
    if config.get('has_bonjour', False):
        ip_bonjour = getBonjourIP()
        if ip_bonjour != None and ip_bonjour != "":
            updater.add(f"{host}-wa", 60, "AAAA", ip_bonjour)

    if config.get('alt_names'):
        alt_names = config.get('alt_names', [])
    
        for alt in alt_names:
            updater.delete(f"{alt}-txt", "TXT")
            updater.add(f"{alt}-txt", 60, "TXT", f"\"Updated: {ts_now}\"")
            updater.delete(f"{alt}", "CNAME")
            updater.add(f"{alt}", 60, "CNAME", f"{host}.{zone}.")

    if config.get('debug', False):
        print("Changes:")
        pprint.pprint(updater.sections)

    response = dns.query.tcp(updater, zone_master)

    if config.get('debug', False):
        print("Result:")
        print(response)
    
    try:
        fcntl.lockf(fp, fcntl.LOCK_UN)
    except IOError:
        # another instance is running
        print("Failed to unlock.")
        sys.exit(1)
    
    os.unlink(PID_FILE)
