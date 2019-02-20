from getIPs import getPublicIPs
from cloudium import Certcrawler
import iptools, argparse

def awsScan(keyword, output, region):
    awsKeywordList = keyword
    awsResult = []
    
    # Get AWS Public IPs
    aws = getPublicIPs("amazon")
    awsIPList = aws.extractAmazonIPs()

    # Scan AWS Public IPs and extract domain including keywords
    awsCrawler = Certcrawler(awsIPList, awsKeywordList, output, region)
    awsCrawler.certScanner()
    awsCrawler.fileWriter()

def azureScan(keyword,output, region):
    azureKeywordList = keyword
    azureResult = []

    # Get Azure Public IPs
    azure = getPublicIPs("azure")
    azureIPList = azure.extractAzureIPs()

    #Scan Azure public IPs and extract domain including keywords
    azureCrawler = Certcrawler(azureIPList, azureKeywordList, output, region)
    azureCrawler.certScanner()

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
    PARSER.add_argument('-r', '--region', help='Targeting specific regions : All, US, Asia, EU, ETC', required=True)
    ARGS = PARSER.parse_args()

    if ARGS.provider == 'amazon':
        awsScan(ARGS.keyword, ARGS.output, ARGS.region)
    elif ARGS.provider == 'azure':
        azureScan(ARGS.keyword, ARGS.output, ARGS.region)

main()
