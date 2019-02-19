# USE THIS FILE FOR TEST SCAN
from cloudium import Certcrawler
import iptools, argparse
from buckethunter import Buckethunter

testawsIPList = ["52.95.245.0/24@us", "52.95.154.0/23@us"]
testazureIpList = ["52.165.32.0/20@uscentral", "157.55.108.0/23@uscentral"]


def awsScan(keyword, output):
    awsKeywordList = keyword

    # Scan AWS Public IPs and extract domain including keywords
    awsCrawler = Certcrawler(testawsIPList, awsKeywordList, output)
    awsCrawler.shuffleList()
    # awsCrawler.certScanner()
    # awsCrawler.fileWriter()

def azureScan(keyword, output):
    azureKeywordList = keyword

    #Scan Azure public IPs and extract domain including keywords
    azureCrawler = Certcrawler(testazureIpList, azureKeywordList, output)
    azureCrawler.certScanner()
    azureCrawler.fileWriter()

    # # Testing Bucket Hunter whether domain is live or not
    # b_hunter = Buckethunter(azureCrawler.returnRes())
    # b_hunter.getDomainList()
    # # b_hunter.printDomain()
    # b_hunter.bucketChecker()

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
    PARSER.add_argument('-o', '--output', help='Output file name', required=True)
    ARGS = PARSER.parse_args()

    if ARGS.provider == 'amazon':
        awsScan(ARGS.keyword, ARGS.output)
    elif ARGS.provider == 'azure':
        azureScan(ARGS.keyword, ARGS.output)


main()
