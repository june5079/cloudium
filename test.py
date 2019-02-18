# from getIPs import getPublicIPs
from cloudium import Certcrawler
import iptools, argparse
from buckethunter import Buckethunter

awsIPList = ["52.95.245.0/24@us", "52.95.154.0/23@us"]
azureIpList = ["52.165.32.0/20@uscentral", "157.55.108.0/23@uscentral"]


def awsScan(keyword):
    awsKeywordList = keyword

    # Scan AWS Public IPs and extract domain including keywords
    awsCrawler = Certcrawler(awsIPList, awsKeywordList)
    awsCrawler.certScanner()

def azureScan(keyword):

    azureKeywordList = keyword

    #Scan Azure public IPs and extract domain including keywords
    azureCrawler = Certcrawler(azureIpList, azureKeywordList)
    azureCrawler.certScanner()
    # print (azureCrawler.returnRes())

    b_hunter = Buckethunter(azureCrawler.returnRes())
    b_hunter.getDomainList()
    # b_hunter.printDomain()
    b_hunter.bucketChecker()

    print ("[+] All Done with scanning Azure ")


def main():
    print ("""
 ______     __         ______     __  __     _____     __     __  __     __    __    
/\  ___\   /\ \       /\  __ \   /\ \/\ \   /\  __-.  /\ \   /\ \/\ \   /\ "-./  \   
\ \ \____  \ \ \____  \ \ \/\ \  \ \ \_\ \  \ \ \/\ \ \ \ \  \ \ \_\ \  \ \ \-./\ \  
 \ \_____\  \ \_____\  \ \_____\  \ \_____\  \ \____-  \ \_\  \ \_____\  \ \_\ \ \_\ 
  \/_____/   \/_____/   \/_____/   \/_____/   \/____/   \/_/   \/_____/   \/_/  \/_/ 
                                                                                    
""")

    PARSER = argparse.ArgumentParser(description="""Cloudioum scans public IPs of cloud providers and extract domain information""")
    PARSER.add_argument('-p', '--provider', help='Input cloud provider : amazon, azure, gcloud', required=True)
    PARSER.add_argument('-k', '--keyword', nargs = "+", help='Input keywords : google, facebook, samsung, Etc.', required=True)
    ARGS = PARSER.parse_args()

    if ARGS.provider == 'amazon':
        awsScan(ARGS.keyword)
    elif ARGS.provider == 'azure':
        azureScan(ARGS.keyword)


main()
