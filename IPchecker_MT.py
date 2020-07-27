#!/usr/bin/env python
# Name:     isthisipbad.py
# Purpose:  Checks Single or Bulk IPs against popular DNS Blackhole Services
# By:       https://github.com/holidayz1
# Date:     27.07.20


import sys
import argparse
import socket
import os
import csv
import json
import dns.resolver # Requires dnspython AKA python-dns package
from urllib.request import urlopen
import concurrent.futures


def load_bldns_json():
    try:
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),'bldns.json'), 'r', encoding='utf8') as f:
            return json.load(f)
    except Exception as err:
        print("Failed to read Configuration file with Error: "+str(err))


def openFile(IPlist):
    try:
        with open(IPlist, 'r') as f:
            data = f.read().splitlines() 
        return data
    except IOError:
        print('There is no file named: '+str(f))


def writeCSV(dataList, opath='NO'):
    if(opath == 'NO'):
        outputfile = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),'output.csv'))
    else:
        base = os.path.basename(opath)
        outputfile = str(os.path.join(os.path.dirname(os.path.realpath(opath)),(str(os.path.splitext(base)[0])+'_output.csv')))
    with open(outputfile, 'w') as myfile:
        for items in dataList:
            myfile.write("%s\n" % items)


def Rep_Check_IP(ip_addr):
    BAD = 0
    GOOD = 0
    message=""
    reversed_dns = socket.getfqdn(ip_addr)
    for bl in bls['bldns']:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(ip_addr).split("."))) + "." + bl
            my_resolver.timeout = 10
            my_resolver.lifetime = 10
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            if(message):
                message=message+' || '+str('Listed in ' + str(bl) + ' (%s: %s)' % (answers[0], answer_txt[0]))
            else:
                message=str('Listed in ' + str(bl) + ' (%s: %s)' % (answers[0], answer_txt[0]))
            BAD = BAD + 1
        except dns.resolver.NXDOMAIN:
            GOOD = GOOD + 1
        except dns.resolver.Timeout:
            print('WARNING: Timeout querying ' + str(bl) + ' for IP '+str(ip_addr)) 
            continue
        except dns.resolver.NoNameservers:
            print('WARNING: No nameservers for ' + str(bl) + ' for IP '+str(ip_addr))
            continue
        except dns.resolver.NoAnswer:
            print('WARNING: No answer for ' + str(bl) + ' for IP '+str(ip_addr))
            continue
    if(message):      
        return str(str(ip_addr)+','+str('{0},{1}'.format(BAD, (GOOD+BAD)))+','+str(reversed_dns)+','+str(message))
    else:
        return str(str(ip_addr)+','+str('{0},{1}'.format(BAD, (GOOD+BAD)))+','+str(reversed_dns))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Is This IP Bad?')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip', help='IP address to check')
    group.add_argument('-f', '--filepath', help='Location of File containing the list of IP addresses to checked')
    args = parser.parse_args()
    delimiter=','
    global bls
    bls = load_bldns_json()
    reslist = list()
    reslist.append("IP"+str(delimiter)+"Result"+str(delimiter)+"DNSBL Checked"+str(delimiter)+"FQDN"+str(delimiter)+"Sightings")
    if args.ip is not None and args.filepath is None: # checking only one IP and Display result in Command Prompt
        msgg=Rep_Check_IP(str(args.ip))
        reslist.append(msgg)
        for result in reslist:
            print(str(result))
        writeCSV(reslist)
    elif args.ip is None and args.filepath is not None: # Do the Magic
        ip_addr_list=openFile(args.filepath)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = executor.map(Rep_Check_IP,ip_addr_list)
            for result in results:
                reslist.append(result)
        writeCSV(reslist,args.filepath)