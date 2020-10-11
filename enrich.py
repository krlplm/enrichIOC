##################################################################################################################################
# Script to fetch the Domain and IP data from Risk IQ, VirusTotal API and to scrape the categorization from Symantec site review using selenium.
# Author : Hem aka Cyberdude
##################################################################################################################################

#from argparse import ArgumentParser
#from bs4 import BeautifulSoup
import json
import requests
import os
import re
from requests.auth import HTTPBasicAuth
from argparse import ArgumentParser
from selenium import webdriver
from time import sleep
from config import user, pwd, apikey    

def fetch_details(urls, user, pwd, entity):
    #global declaration below so that these variables are available for code inside main()
    global classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results, osint_results
    for ptUrl in urls:
        if ptUrl == ptEnrichUrl:
            payload = {'query': entity}
            headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8', 'User-Agent': 'Mozilla/5.0'}
            #In earlier requests version, params was replaced by data
            resp = requests.get(ptUrl,
                    params = payload,
                    headers = headers,
                    auth=HTTPBasicAuth(user, pwd))

            jsonResp = resp.json()
            #The original json values had non-json quotes which we are replacing with double quotes.
            #Also, strings like True, False, None are causing problems for which we are replacing them using nested replace function
            jsonResponse = str(jsonResp).replace('\'', '\"').replace('False','\"False\"').replace('None','[]').replace('True','\"True\"')
            #print(jsonResponse)
            #Converting json string objects to json dictionary
            try:
                pt_dict = json.loads(jsonResponse)
                classification = pt_dict['classification']
                sinkhole = pt_dict['sinkhole']
                everCompromised = pt_dict['everCompromised']
                count_of_subdom = len(pt_dict['subdomains'])
                dynamicDns = pt_dict['dynamicDns']
            except:
                #print('Error in parsing Enrichment json data for:', entity)
                count_of_subdom="JSON_Error"
                classification="JSON_Error"
                dynamicDns="JSON_Error"
                continue
        elif ptUrl == ptMalwareUrl:
            payload = {'query': entity}
            headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8', 'User-Agent': 'Mozilla/5.0'}
            #In earlier requests version, params was replaced by data
            resp = requests.get(ptUrl,
                    params = payload,
                    headers = headers,
                    auth=HTTPBasicAuth(user, pwd))

            jsonResp = resp.json()
            #The original json values had non-json quotes which we are replacing with double quotes.
            #Also, strings like True, False, None are causing problems for which we are replacing them using nested replace function
            jsonResponse = str(jsonResp).replace('\'', '\"').replace('False','\"False\"').replace('None','[]').replace('True','\"True\"')
            #print(jsonResponse)
            #Converting json string objects to json dictionary
            try:
                pt_dict = json.loads(jsonResponse)
                mal_results = len(pt_dict['results'])
            except:
                #print('Error in parsing Malware json data for:', entity)
                mal_results = 'null'
                continue
        else:
            payload = {'query': entity}
            headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8', 'User-Agent': 'Mozilla/5.0'}
            #In earlier requests version, params was replaced by data
            resp = requests.get(ptUrl,
                    params = payload,
                    headers = headers,
                    auth=HTTPBasicAuth(user, pwd))

            jsonResp = resp.json()
            #The original json values had non-json quotes which we are replacing with double quotes.
            #Also, strings like True, False, None are causing problems for which we are replacing them using nested replace function
            jsonResponse = str(jsonResp).replace('\'', '\"').replace('False','\"False\"').replace('None','[]').replace('True','\"True\"')
            #print(jsonResponse)
            #Converting json string objects to json dictionary
            try:
                pt_dict = json.loads(jsonResponse)
                osint_results = len(pt_dict['results'])
            except:
                #print('Error in parsing OSINT json data for:', entity)
                osint_results = 'null'
                continue
    return classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results, osint_results

class siteReview():
    def __init__(self):
        #To instantiate the chrome browser
        self.driver = webdriver.Chrome()

    def ioc_search(self, entity):
        # self.driver.get('https://sitereview.bluecoat.com/#/')
        url = 'https://sitereview.bluecoat.com/#/lookup-result/' + entity
        self.driver.get(url)
        #With out this sleep function, the site review rejects the requests. This will help to throttle the requests.
        sleep(6)

        try:
            cat = self.driver.find_element_by_xpath('//*[@id="submissionForm"]/span/span[1]/div/div[2]/span[1]/span')
            if self.driver.find_element_by_xpath('//*[@id="submissionForm"]/span/span[1]/div/div[2]/span[2]/span'):
                cat2 = self.driver.find_element_by_xpath('//*[@id="submissionForm"]/span/span[1]/div/div[2]/span[2]/span')
                if "Last Time" in cat2.text:
                    category = cat.text
                else:
                    category = cat.text + "|" + cat2.text
            else:
                category = cat.text
        except:
            category = 'error'
        return category


def lst_parse(lst, urls, user, pwd, apikey):
    bot = siteReview()
    with open(os.path.join(lst), 'r') as f:
        for ent in f:
            entity = ent.strip()
            #print('Processing:', entity)
            fetch_details(urls, user, pwd, entity)

            val = bot.ioc_search(entity)

            # VT Processing
            ip_regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
                        25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
                        25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
                        25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
            if (re.search(ip_regex, entity)):
                url = 'https://www.virustotal.com/api/v3/ip_addresses/' + entity
                headers = {'x-apikey': apikey}
                response = requests.get(url, headers=headers)
                vtResp = response.json()
                if response.status_code == 200:
                    # print(vtResp)
                    # We are using string replacement below to adjust the JSON response to be loaded into python dictionary
                    # vtResponse = str(vtResp).replace('Let\'s', 'Lets').replace('\'', '\"').replace('None','[]').replace('False','\"False\"').replace('True','\"True\"')
                    vt_str = json.dumps(vtResp['data'])
                    vt_dict = json.loads(vt_str)
                    # print(vt_dict)
                    try:
                        attr = vt_dict['attributes']
                        as_own = attr['as_owner']
                        asn = attr['asn']
                        stats = attr['last_analysis_stats']
                        network = attr['network']
                        reputation = attr['reputation']
                        tags = attr['tags']
                    except:
                        attr = 'null'
                        as_own = 'null'
                        asn = 'null'
                        stats = 'null'
                        network = 'null'
                        reputation = 'null'
                        tags = 'null'
                else:
                    attr = 'VT Error'
                    as_own = 'VT Error'
                    asn = 'VT Error'
                    stats = 'VT Error'
                    network = 'VT Error'
                    reputation = 'VT Error'
                    tags = 'VT Error'

                cats = 'AS Owner' + '-' + str(as_own).replace(',', '') + '|' + 'ASN' + '-' + str(
                    asn) + '|' + 'Stats' + '-' + str(stats).replace(', ', ';').replace('{', '').replace('}',
                                                                                                        '').replace(
                    '\'', '') + '|' + 'Network' + '-' + str(network) + '|' + 'Reputation Score' + '-' + str(
                    reputation) + '|' + 'Tags' + '-' + str(tags).replace('[', '').replace(']', '')
                print(entity, classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results,
                      osint_results, cats, val, sep=",")

            else:
                url = 'https://www.virustotal.com/api/v3/domains/' + entity
                headers = {'x-apikey': apikey}
                response = requests.get(url, headers=headers)
                vtResp = response.json()
                if response.status_code == 200:
                    # print(vtResp)
                    # We are using string replacement below to adjust the JSON response to be loaded into python dictionary
                    # vtResponse = str(vtResp).replace('Let\'s', 'Lets').replace('\'', '\"').replace('None','[]').replace('False','\"False\"').replace('True','\"True\"')
                    vt_str = json.dumps(vtResp['data'])
                    vt_dict = json.loads(vt_str)
                    # print(vt_dict)
                    try:
                        attr = vt_dict['attributes']
                        cats = attr['categories']
                        stats = attr['last_analysis_stats']
                        # print(cats)
                        cats = str(cats).replace(', ', '|').replace('{', '').replace('}', '').replace('\'', '')
                        stats = str(stats).replace(', ', ';').replace('{', '').replace('}','').replace('\'', '')
                    except:
                        cats = 'null'
                        stats = 'null'
                else:
                    cats = 'VT Error'
                    stats = 'VT Error'

                vt_data = cats + '|' + stats
                print(entity, classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results,
                      osint_results, vt_data, val, sep=",")


def cmd_parse(cmd, urls, user, pwd, apikey):
    entity = cmd
    fetch_details(urls, user, pwd, entity)
    bot = siteReview()
    val = bot.ioc_search(entity)

    # VT Processing
    ip_regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
                          25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
                          25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
                          25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
    if (re.search(ip_regex, entity)):
        url = 'https://www.virustotal.com/api/v3/ip_addresses/' + entity
        headers = {'x-apikey': apikey}
        response = requests.get(url, headers=headers)
        vtResp = response.json()
        if response.status_code == 200:
            # print(vtResp)
            # We are using string replacement below to adjust the JSON response to be loaded into python dictionary
            # vtResponse = str(vtResp).replace('Let\'s', 'Lets').replace('\'', '\"').replace('None','[]').replace('False','\"False\"').replace('True','\"True\"')
            vt_str = json.dumps(vtResp['data'])
            vt_dict = json.loads(vt_str)
            # print(vt_dict)
            try:
                attr = vt_dict['attributes']
                as_own = attr['as_owner']
                asn = attr['asn']
                stats = attr['last_analysis_stats']
                network = attr['network']
                reputation = attr['reputation']
                tags = attr['tags']
            except:
                attr = 'null'
                as_own = 'null'
                asn = 'null'
                stats = 'null'
                network = 'null'
                reputation = 'null'
                tags = 'null'
        else:
            attr = 'VT Error'
            as_own = 'VT Error'
            asn = 'VT Error'
            stats = 'VT Error'
            network = 'VT Error'
            reputation = 'VT Error'
            tags = 'VT Error'

        cats = 'AS Owner' + '-' + str(as_own).replace(',', '') + '|' + 'ASN' + '-' + str(
          asn) + '|' + 'Stats' + '-' + str(stats).replace(', ', ';').replace('{', '').replace('}',
                                                                                              '').replace(
          '\'', '') + '|' + 'Network' + '-' + str(network) + '|' + 'Reputation Score' + '-' + str(
          reputation) + '|' + 'Tags' + '-' + str(tags).replace('[', '').replace(']', '')
        print(entity, classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results,
            osint_results, cats, val, sep=",")

    else:
        url = 'https://www.virustotal.com/api/v3/domains/' + entity
        headers = {'x-apikey': apikey}
        response = requests.get(url, headers=headers)
        vtResp = response.json()
        if response.status_code == 200:
            # print(vtResp)
            # We are using string replacement below to adjust the JSON response to be loaded into python dictionary
            # vtResponse = str(vtResp).replace('Let\'s', 'Lets').replace('\'', '\"').replace('None','[]').replace('False','\"False\"').replace('True','\"True\"')
            vt_str = json.dumps(vtResp['data'])
            vt_dict = json.loads(vt_str)
            # print(vt_dict)
            try:
                attr = vt_dict['attributes']
                cats = attr['categories']
                # print(cats)
                cats = str(cats).replace(', ', '|').replace('{', '').replace('}', '').replace('\'', '')
            except:
                cats = 'null'
        else:
            cats = 'VT Error'

        print(entity, classification, sinkhole, everCompromised, count_of_subdom, dynamicDns, mal_results,
            osint_results, cats, val, sep=",")


def main():
    #Creating a list of URLs
    global ptEnrichUrl, ptMalwareUrl, ptOsintUrl
    ################### Passive Total URLs ########################
    ptEnrichUrl = "https://api.passivetotal.org/v2/enrichment"
    ptMalwareUrl = "https://api.passivetotal.org/v2/enrichment/malware"
    ptOsintUrl = "https://api.passivetotal.org/v2/enrichment/osint"
    #################################################

    urls = [ptEnrichUrl, ptMalwareUrl, ptOsintUrl]

    p = ArgumentParser()
    p.add_argument("-l", "--lst", type=str, help="Submit domain/IP list separated by new line specifying the absolute path of file")
    p.add_argument("-c", "--cmd", type=str, help="Enter the single domain/IP")
    args = p.parse_args()
    if args.lst:
        print('ioc,classification,sinkhole,everCompromised,subdomains,dynamicDns,mal_results,osint_results,VT_Data,Symantec_Sitereview')
        lst_parse(args.lst, urls, user, pwd, apikey)
    elif args.cmd:
        print('ioc,classification,sinkhole,everCompromised,subdomains,dynamicDns,mal_results,osint_results,VT_Data,Symantec_Sitereview')
        cmd_parse(args.cmd, urls, user, pwd, apikey)
    else:
        print("\n" + "Note: Please supplement the single domain/IP by using switch -c or a list of domains/IPs with the path by using switch -l" + "\n")


if __name__ == "__main__":
    main()
else:
    pass
