import requests, subprocess, time
import OpenSSL, M2Crypto, ssl, socket
import iptools
import random
from termcolor import colored, cprint
# from multiprocessing import Process, Queue, Lock, Pool ---> is not stable with tqdm lib
from tqdm import tqdm
from pathos.multiprocessing import ProcessingPool as Pool # Used for tqdm instead of pool

class Certcrawler:

    def __init__(self, ipAddrList, keywordList, outputFile, region):
        socket.setdefaulttimeout(1)

        self.allipAddrList = ipAddrList
        self.keywordList = keywordList
        self.resList = []
        self.tryipList = []
        self.ipExtractResult = []
        self.totalRes = []
        self.outputFile = outputFile
        self.region = region

        cprint ("[+] Start Cloudium certfication scanner ", 'green')

    def ipExtract(self, ipClass):
        # Extract specific ip addrs from IP Class
        self.IPV4 = ipClass
        self.tryipList = iptools.IpRange(self.IPV4)

        return self.tryipList
   
    def shuffleList(self):
        # Shuffle Target IP Lists for avoiding abusing from providers
        self.shuffledIPList = random.sample(self.allipAddrList, len(self.allipAddrList))
        return self.shuffledIPList

    def certScanner (self) :
        p = Pool(nodes = 512)
        cprint ("[+] Keywords : " + " ".join(str(x) for x in self.keywordList), 'green')
        # self.allipAddrList = self.shuffleList()
        self.allipAddrList = [x for x in self.shuffleList() if self.region in x ]
        
        for self.tryipClass in self.allipAddrList:
            self.ipExtractResult = self.ipExtract(self.tryipClass.split("@")[0])
            _max = len(self.ipExtractResult)
            cprint ("[+] Scanning IP Addr Class : " + self.tryipClass + "\t-- Number of scan target is :" + str(len(self.ipExtractResult)), 'green')

            with tqdm(total=_max) as pbar:
                pbar.set_description("[+] Progressing : %s " %self.tryipClass)
                for i, domain in tqdm(enumerate(p.imap(self.certChecker, self.ipExtractResult))):
                    pbar.update()
                    if domain is not None:
                        self.resList.append(domain)
                pbar.close()
                p.terminate() # Like p.close()
                p.restart() # Like p.join()

            if self.resList:
                self.printRes()

            else:
                cprint ("[!] No kewords found on this IP class \n", 'red')

            time.sleep(1)
            self.ipExtractResult = []
            self.resList = []

    def certChecker(self, tryip):
        try:
            cert = ssl.get_server_certificate((tryip, 443))
            x509 = M2Crypto.X509.load_cert_string(cert)
            cnDomain = x509.get_subject().as_text().split("CN=")[1]

            for x in self.keywordList:
                if x in cnDomain:
                    return cnDomain
                else:
                    pass
        except:
            pass

    def printRes (self) :
        # Delete duplicated data
        self.resSet = set(self.resList)
        self.totalRes.extend(self.resSet)

        cprint ("[+] Number of result is : " + str(len(self.resSet)), 'yellow')
        for x in self.resSet:
            print (x)
    
    def returnRes (self):
        return self.totalRes
    
    def fileWriter (self):
        f = open(self.outputFile, "w+")
        for x in self.totalRes:
            f.write(x + "\n")
        



