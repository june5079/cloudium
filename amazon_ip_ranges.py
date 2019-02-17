#!/usr/bin/env python

from __future__ import print_function
import requests

def merge_prefixes(payload):
    regions, services = {}, {}

    for prefix in payload['prefixes']:
        ip_prefix = prefix['ip_prefix']

        _regions = regions.setdefault(ip_prefix, [])
        _regions.append(prefix['region'])
        regions[ip_prefix] = _regions

        _services = services.setdefault(ip_prefix, [])
        _services.append(prefix['service'])
        services[ip_prefix] = _services

    merged = []

    for prefix in payload['prefixes']:
        ip_prefix = prefix['ip_prefix']
        prefix_tuple = (ip_prefix, regions[ip_prefix], services[ip_prefix])
        merged.append(prefix_tuple)

    return merged


def prefixes(includes=None, excludes=None, regions=None):
    r = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
    payload = r.json()

    if not includes:
        includes = []

    if not excludes:
        excludes = []

    if not regions:
        regions = []

    def valid_region(_regions):
        if not regions:
            return True

        for region in regions:
            if region in _regions:
                return True

    def valid_service(_services):
        for exclude in excludes:
            if exclude in _services:
                return False

        if not includes:
            return True

        for include in includes:
            if include in _services:
                return True

    filtered = []

    for ip_prefix, _regions, _services in merge_prefixes(payload):
        if valid_region(_regions):
            if valid_service(_services):
                filtered.append(ip_prefix)

    return filtered

if __name__ == '__main__':
    #print(prefixes(includes=['AMAZON'], excludes=['EC2'], regions=['us-east-1']))

    # Extract IPv4 addresses
    Amazon_IPs_List = prefixes()
    # Remove duplicated data
    RemoveDup_Amazon_IPs_List = list(set(Amazon_IPs_List))
    RemoveDup_Amazon_IPs_List.sort()

    for IPv4_Class in RemoveDup_Amazon_IPs_List:
    	print (IPv4_Class)

    #print(Amazon_IPs_List)
