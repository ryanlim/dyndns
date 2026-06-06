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

import socket
import fcntl
import struct
import ipaddress

import dns.tsigkeyring
import dns.update
import dns.query
import dns.resolver
import dns.inet

import netifaces


USER = os.environ.get('USER', os.environ.get('LOGNAME', 'undefined_user'))
PID_FILE = f"/tmp/nsupdate-{USER}.pid"

URLLIB_TIMEOUT = 10
DNSPYTHON_TIMEOUT = 10


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

    if res is None:
        #print "Cannot obtain public IP v%s address: %s" % (addr_type, e)
        return None

    res_json = json.loads(res.read())
    candidates = res_json.get('ip_candidates', [])
    if not candidates:
        return None
    return candidates[0]['ip']


def getBonjourIP():
    try:
        bonjour_interface = netifaces.ifaddresses('utun0')
        ip_bonjour = bonjour_interface[netifaces.InterfaceType.AF_INET6][0]['addr'].split('%')[0]
        return ip_bonjour
    except (KeyError, IndexError):
        return None


def getLocalIP():
    try:
        default_iface = netifaces.default_gateway()[netifaces.InterfaceType.AF_INET][1]
        ip = netifaces.ifaddresses(default_iface)[netifaces.InterfaceType.AF_INET][0]['addr']
        return ip
    except (KeyError, IndexError):
        return None

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])

def getSLAACIPv6Addr():
    default_iface = netifaces.default_gateway()[netifaces.InterfaceType.AF_INET6][1]
    links = netifaces.ifaddresses(default_iface)[netifaces.InterfaceType.AF_INET6]

    mac_addr = getHwAddr(default_iface)
    global_stable_ipv6 = ""

    for link in links:
        m_ = mac_addr.split(":")
        part_ipv6_addr = f"{m_[3]}:{m_[4]}{m_[5]}"

        if 'addr' in link and \
                part_ipv6_addr in link['addr'] and \
                ipaddress.ip_address(link['addr']).is_global:
            return link['addr']

    return None


def getConfig(config_path):
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except Exception:
        print(f"{config_path} not found or invalid json file.")
        sys.exit(1)

    if 'endpoint' in config or 'bearer_token' in config:
        http_required = ('zone', 'host', 'endpoint', 'bearer_token')
        for c in http_required:
            if c not in config:
                print(f"Missing {c} option in the config file.")
                sys.exit(1)
    else:
        min_config = ('zone', 'zone_master', 'host', 'tsigkeyring')
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


def buildHttpOperations(config, ts_now, ip4_address, ip6_address):
    ops = []
    zone = config.get('zone')
    host = config.get('host')
    fqdn = f"{host}.{zone}"
    ttl = 60

    ops.append({"name": fqdn, "type": "TXT", "action": "replace", "value": f"Updated on: {ts_now}", "ttl": ttl})

    if ip4_address:
        ops.append({"name": fqdn, "type": "A", "action": "replace", "value": ip4_address, "ttl": ttl})
    else:
        ops.append({"name": fqdn, "type": "A", "action": "delete"})

    if ip6_address:
        ops.append({"name": fqdn, "type": "AAAA", "action": "replace", "value": ip6_address, "ttl": ttl})
    else:
        ops.append({"name": fqdn, "type": "AAAA", "action": "delete"})

    local_fqdn = f"{host}-local.{zone}"
    if config.get('has_local', False):
        ip_local = getLocalIP()
        if ip_local:
            ops.append({"name": local_fqdn, "type": "A", "action": "replace", "value": ip_local, "ttl": ttl})
        else:
            ops.append({"name": local_fqdn, "type": "A", "action": "delete"})
    else:
        ops.append({"name": local_fqdn, "type": "A", "action": "delete"})

    wa_fqdn = f"{host}-wa.{zone}"
    if config.get('has_bonjour', False):
        ip_bonjour = getBonjourIP()
        if ip_bonjour:
            ops.append({"name": wa_fqdn, "type": "AAAA", "action": "replace", "value": ip_bonjour, "ttl": ttl})
        else:
            ops.append({"name": wa_fqdn, "type": "AAAA", "action": "delete"})
    else:
        ops.append({"name": wa_fqdn, "type": "AAAA", "action": "delete"})

    for alt in config.get('alt_names', []):
        ops.append({"name": f"{alt}-txt.{zone}", "type": "TXT", "action": "replace", "value": f"Updated: {ts_now}", "ttl": ttl})
        ops.append({"name": f"{alt}.{zone}", "type": "CNAME", "action": "replace", "value": f"{fqdn}.", "ttl": ttl})

    return ops


def sendHttpUpdate(operations, endpoint, token, timeout=URLLIB_TIMEOUT):
    data = json.dumps(operations).encode('utf-8')
    req = urllib.request.Request(endpoint, data=data, method='POST')
    req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Content-Type', 'application/json')
    res = urllib.request.urlopen(req, timeout=timeout)
    return json.loads(res.read())


if __name__ == "__main__":
    fp = open(PID_FILE, 'w')
    try:
        fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        # another instance is running
        print("Another instance is running.")
        fp.close()
        sys.exit(1)

    try:
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
            if config_.get('bearer_token'):
                config_['bearer_token'] = "redacted"

            pprint.pprint(config_, indent=4)

        zone = config.get('zone')
        host = config.get('host')
        tsigkeyring = config.get('tsigkeyring', {})

        ip4_address = getPublicIP('4', config.get('urllib_timeout', URLLIB_TIMEOUT))
        if config.get('debug', False):
            print(f"IPv4: {ip4_address}")

        ip6_address = None

        if config.get('use_ipv6_slaac', False):
            ip6_address = getSLAACIPv6Addr()
            if config.get('debug', False):
                print(f"IPv6 (SLAAC): {ip6_address}")

            if not ip6_address:
                ip6_address = getPublicIP('6', config.get('urllib_timeout', URLLIB_TIMEOUT))
        else:
            ip6_address = getPublicIP('6', config.get('urllib_timeout', URLLIB_TIMEOUT))

        if config.get('debug', False):
            print(f"IPv6: {ip6_address}")

        ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %z")

        use_http = 'endpoint' in config and 'bearer_token' in config

        if use_http:
            ops = buildHttpOperations(config, ts_now, ip4_address, ip6_address)
            if config.get('debug', False):
                print("Operations:")
                pprint.pprint(ops)
            results = sendHttpUpdate(
                ops,
                config['endpoint'],
                config['bearer_token'],
                config.get('urllib_timeout', URLLIB_TIMEOUT)
            )
            if config.get('debug', False):
                print("Result:")
                pprint.pprint(results)
            for r in results:
                if r.get('status') != 'ok':
                    print(f"DNS update failed for {r['name']} {r['type']}: {r.get('error', r.get('rcode', 'unknown'))}")
                    sys.exit(1)
        else:
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

            response = dns.query.tcp(
                updater,
                zone_master,
                config.get('dnspython_timeout', DNSPYTHON_TIMEOUT)
            )

            if config.get('debug', False):
                print("Result:")
                print(response)

            if response.rcode() != dns.rcode.NOERROR:
                print(f"DNS update failed: {dns.rcode.to_text(response.rcode())}")
                sys.exit(1)

    finally:
        fcntl.lockf(fp, fcntl.LOCK_UN)
        fp.close()
        os.unlink(PID_FILE)
