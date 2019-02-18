import requests
from termcolor import colored, cprint

class Buckethunter:

    def __init__(self, domainList):
        # domainList is results from cloudium scanner
        self.domainList = domainList
    
    def getDomainList(self):
        self.domainList_ = []
        cprint('[+] Checking whether Bucket is empty ', 'green')
        for x in self.domainList:
            if "*" in x:
                self.domainList_.append(x.split("*.")[1])
            else:
                self.domainList_.append(x)
    
    def bucketChecker(self):
        
        for x in self.domainList_:
            try :
                print ("trying + "+ x)
                r = requests.get("https://"+x, timeout = 1)
                if r.status_code == 404:
                    print ("404 " + x)
                else:
                    print (str(r.status_code) + " " + str(x))
                
            except requests.exceptions.RequestException as e:
                # print (e)
                pass

    def printDomain(self):
        for x in self.domainList_:
            print (x)



        