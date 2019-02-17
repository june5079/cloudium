from getIPs import getPublicIPs
from cloudium import certCrawler
import iptools, argparse



def awsScan(keyword):
    awsKeywordList = keyword
    awsIPList = ["52.95.245.0/24@us", "52.95.154.0/23@us"]
    awsResult = []
    
    # Get AWS Public IPs
    # aws = getPublicIPs("amazon")
    # awsIPList = aws.extractAmazonIPs()

    # Scan AWS Public IPs and extract keywords
    awsCrawler = certCrawler(awsIPList, awsKeywordList)
    awsCrawler.certScanner()


def main():
    print ("""
 ______     __         ______     __  __     _____     __     __  __     __    __    
/\  ___\   /\ \       /\  __ \   /\ \/\ \   /\  __-.  /\ \   /\ \/\ \   /\ "-./  \   
\ \ \____  \ \ \____  \ \ \/\ \  \ \ \_\ \  \ \ \/\ \ \ \ \  \ \ \_\ \  \ \ \-./\ \  
 \ \_____\  \ \_____\  \ \_____\  \ \_____\  \ \____-  \ \_\  \ \_____\  \ \_\ \ \_\ 
  \/_____/   \/_____/   \/_____/   \/_____/   \/____/   \/_/   \/_____/   \/_/  \/_/ 
                                                                                    
""")
    tmpList = []

    PARSER = argparse.ArgumentParser(description="""Cloudioum scans public IPs of cloud providers and extract domain information""")
    PARSER.add_argument('-p', '--provider', help='Input cloud provider : amazon, azure, gcloud', required=True)
    PARSER.add_argument('-k', '--keyword', nargs = "+", help='Input keywords : google, facebook, samsung, Etc.', required=True)
    ARGS = PARSER.parse_args()

    if ARGS.provider == 'amazon':
        awsScan(ARGS.keyword)



main()

# # for x in awsIPLists :
# #     print (x)