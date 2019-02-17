import requests, subprocess, time
import OpenSSL, M2Crypto, ssl, socket
import iptools
from termcolor import colored, cprint
# from multiprocessing import Process, Queue, Lock, Pool
from tqdm import tqdm
from pathos.multiprocessing import ProcessingPool as Pool

class certCrawler:

    def __init__(self, ipAddrList, keywordList):
        socket.setdefaulttimeout(1)

        self.allipAddrList = ipAddrList
        self.keywordList = keywordList
        self.resList = []
        self.tryipList = []
        self.ipExtractResult = []

        cprint ("[+] Start certCrawler ", 'green')

    def ipExtract(self, ipClass):
        # Extract specific ip addrs from IP Class
        self.IPV4 = ipClass
        self.tryipList = iptools.IpRange(self.IPV4)

        return self.tryipList

    def certScanner (self) :
        p = Pool(nodes = 256)
  
        count = 0

        for self.tryipClass in self.allipAddrList:
            
            self.ipExtractResult = self.ipExtract(self.tryipClass.split("@")[0])
            _max = len(self.ipExtractResult)
            cprint ("[+] Scanning IP Addr Class : " + self.tryipClass + "\tNumber of scan target is :" + str(len(self.ipExtractResult)), 'green')
            cprint ("[+] Keywords : " + " ".join(str(x) for x in self.keywordList), 'green')

            with tqdm(total=_max) as pbar:
                for i, domain in tqdm(enumerate(p.imap(self.certChecker, self.ipExtractResult))):
                    pbar.update()
                    if domain is not None:
                        self.resList.append(domain)
                print ("\n")
            pbar.close()
            p.close()
            p.join()
            self.printRes()
            time.sleep(2)
            count+=1
            self.ipExtractResult = []

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
        print ("\n########################################################")
        cprint ("number of result is : " + str(len(self.resList)), 'green')
        for x in self.resList:
            print (x)

