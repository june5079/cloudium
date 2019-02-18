from __future__ import print_function
import requests, subprocess, time
from termcolor import colored, cprint
from xml.etree import ElementTree
from bs4 import BeautifulSoup


class getPublicIPs:
    amazonURL = 'https://ip-ranges.amazonaws.com/ip-ranges.json' # From AWS
    azureURL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653' # from MS Azure
    cmdline = './getgcloudpip.sh > gcloudpip.txt'
    cmdline2 = 'rm gcloudpip.txt'
    
    def __init__(self, provider):
        self.provider = provider

        if (self.provider == 'amazon') :
            cprint ("[+] Starting extraction from + " + provider, 'green')
            # self.extractAmazonIPs(self.provider)
        elif (self.provider == 'azure') :
            cprint ("[+] Starting extraction from + " + provider, 'green')
            # self.extractAzureIPs(provider)
        elif (self.provider == 'gcloud'):
            cprint ("[+] Starting extraction from + " + provider, 'green')
            process = subprocess.Popen(self.cmdline, shell=True)
            output, error = process.communicate()
            # process.kill()
            # time.sleep(2)
            self.parseTxt('gcloudpip.txt')
            process = subprocess.Popen(self.cmdline2, shell=True)
            cprint ("[+] Done with extraction + ", 'green')

        else :
            cprint ("[!] Wrong usage" , 'red')
            
    def extractAmazonIPs (self):
        self.amazonpip = []
        r = requests.get(self.amazonURL)
        res = r.json()

        for x in res['prefixes']:
            # if 'us' in x['region']:
            # cprint (x['ip_prefix'] + "@" +  x['region'], 'green', 'on_red')
            self.amazonpip.append(x['ip_prefix'] + "@" +  x['region'])
            # else:
            # print (x['ip_prefix'] + "@" +  x['region'])
        print ("[+] Done with " + self.provider)
        return self.amazonpip

    def extractAzureIPs (self):
        self.azurepip = []
        r = requests.get(self.azureURL)
        res = r.text
        soup = BeautifulSoup(res, 'html.parser')
        downloadurl = soup.select('#c50ef285-c6ea-c240-3cc4-6c9d27067d6c')
        
        for x in downloadurl:
            realurl = x.get('href')
            cprint ("[!] Real download url is " + realurl , 'green')
            cprint ("[+] Trying to download public azure IPs ", 'green')
        
        r2 = requests.get(realurl)
        self.parseXml(r2.content)
        return self.azurepip
    
    def parseXml (self, xmlraw):

        tree = ElementTree.fromstring(xmlraw)
        for child in tree:
            for child2nd in child:
                region = child.attrib['Name']
                pip = child2nd.attrib['Subnet']
                print (pip + "@" + region)
                self.azurepip.append(pip + "@" + region)
        cprint ("[+] Azure public ip has been sucessfully extracted ", 'green')

    def parseTxt (self, textfile):
        self.gcloudpip = []
        f = open(textfile, 'r')
        pips = f.readlines()
        for x in pips:
            self.gcloudpip.append(x.strip("\n"))    
        for y in self.gcloudpip:
            print (y)



