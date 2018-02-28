#Author: Ron Nair
#Date: 28/02/2018
#Email: joutei@icloud.com
#Version: 1.0

import urllib.parse
import urllib.request
import re

print('\n Please enter the IP you would like to check:')
userINPUT = input()
print('\nin progress.......\n')

customheader = {
    'User-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:58.0) Gecko/20100101 Firefox/58.0'
}

customheaderTalos = {
    'Host' : 'www.talosintelligence.com',
    'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:58.0) Gecko/20100101 Firefox/58.0',
    'Accept' : 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language' : 'en-US,en;q=0.5',
    'Accept-Encoding' : 'gzip, deflate, br',
    'Referer' : 'https://www.talosintelligence.com/reputation_center/lookup?search=' + userINPUT,
    'Connection' : 'keep-alive'
}

customheaderIBM = {
    'Accept' : 'application/json, text/plain, */*',
    'Accept-Language' : 'en-US,en;q=0.5',
    'Connection' : 'keep-alive',
    'Host' : 'exchange.xforce.ibmcloud.com',
    'Referer' : 'https://exchange.xforce.ibmcloud.com/ip/' + userINPUT,
    'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:58.0) Gecko/20100101 Firefox/58.0',
    'x-ui' : 'XFE'

}

def reqIPVOID():
    url = 'http://www.ipvoid.com/ip-blacklist-check/'
    values = {'ip' : userINPUT}
    data = urllib.parse.urlencode(values)
    data = data.encode('utf-8')
    req = urllib.request.Request(url, data, headers=customheader)
    resp = urllib.request.urlopen(req)
    respData = resp.read()
    convertedRespData = str(respData)

    blacklist_status = re.findall(r'label-danger">(?P<BLACKLIST>[^<]+)<',convertedRespData)
    reverse_dns = re.findall(r'<td>Reverse\sDNS</td><td>(?P<RDNS>[^<]+)<',convertedRespData)
    asn_owner = re.findall(r'ASN\sOwner</td><td>(?P<ASNOWNER>[^<]+)</td>',convertedRespData)
    country_code = re.findall(r'Country\sCode</td><td>[^>]+>(?P<COUNTRY>[^<]+)</td>',convertedRespData)


    print('\n Current Threat Intel for IP: ' + userINPUT)
    print('\nIPVoid:')
    print('\nBlacklist Status: ' + " ".join(blacklist_status))
    print('Reverse DNS: ' + " ".join(reverse_dns))
    print('ASN Owner: ' + " ".join(asn_owner))
    print('Country Code: ' + " ".join(country_code))
    print('\n')

def reqAbuseipdb():

    url = ('https://www.abuseipdb.com/check/' + userINPUT)
    req = urllib.request.Request(url, headers=customheader)
    resp = urllib.request.urlopen(req)
    respData = resp.read()
    convertedRespData = str(respData)

    reported_x = re.findall(r'<p>This\sIP\swas\sreported\s<b>(?P<REPORTED>[^<]+)</b>',convertedRespData)
    confidence_x = re.findall(r'Confidence\sof\sAbuse\sis\s<b>(?P<CONFIDENCE>[^<]+)</b>',convertedRespData)
    categories_x = re.findall(r'title="[^>]+>(?P<CATEGORIES>[^<]+)</span>',convertedRespData)

    print('AbuseIPDB:')
    print('\nReported: ' + " ".join(reported_x) + ' times')
    print('Confidence: ' + " ".join(confidence_x))
    print('Categories: ' + ",".join(set(categories_x)))
    print('\n')

def reqTalosIntel():

    url = ('https://www.talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fip%2F&query_entry=' + userINPUT + '&offset=0&order=ip+asc')
    req = urllib.request.Request(url, headers=customheaderTalos)
    resp = urllib.request.urlopen(req)
    respData = resp.read()
    convertedRespData = str(respData)

    monthly_spam_level = re.findall(r'"monthly_spam_level":(?P<MONTHLY_SPAM>[^,]+)+',convertedRespData)
    daily_spam_level = re.findall(r'"daily_spam_level":(?P<DAILY_SPAM>[^,]+)+',convertedRespData)
    email_score_name = re.findall(r'"email_score_name":"(?P<EMAIL_SCORE>[^"]+)+',convertedRespData)
    web_score_name = re.findall(r'"web_score_name":"(?P<WEB_SCORE>[^"]+)+',convertedRespData)

    print('Talos Intelligence:')
    print('\nMonthly Spam Level: ' + " ".join(monthly_spam_level))
    print('Daily Spam Level: ' + " ".join(daily_spam_level))
    print('Email Score: ' + " ".join(email_score_name))
    print('Web Score: ' + " ".join(web_score_name))
    print('\n')

def reqIbmIntel():

    url = ('https://exchange.xforce.ibmcloud.com/api/ipr/' + userINPUT)
    req = urllib.request.Request(url, headers=customheaderIBM)
    resp = urllib.request.urlopen(req)
    respData = resp.read()
    convertedRespData = str(respData)

    ibm_reason = re.findall(r'"reason":"(?P<REASON>[^"]+)+',convertedRespData)
    ibm_reason_description = re.findall(r'"reasonDescription":"(?P<REASON_DESCRIPTION>[^"]+)+',convertedRespData)

    ibm_categories = re.findall(r'"cats":{(?P<CATS>[^\}]+)+',convertedRespData)
    ibm_categories_X = [cat + "%" for cat in ibm_categories]

    ibm_score = re.findall(r'"score":(?P<SCORE>[^\}]+)},{"created"',convertedRespData)
    ibm_score_X = [score + "%" for score in ibm_score]

    print('IBM X-Force:')
    print('\n Reason:\n  * ' + '\n  * '.join(set(ibm_reason)))
    print('\n')
    print(' Reason Description:\n  * ' + '\n  * '.join(set(ibm_reason_description)))
    print('\n')
    print(' Reported Categories:\n  * ' + '\n  * '.join(set(ibm_categories_X)))
    print('\n')
    print(' Reported Risks:\n  * ' + '\n  * '.join(set(ibm_score_X)))
    print('\n')



#RUN FUNCTIONS
reqIPVOID()
reqTalosIntel()
reqIbmIntel()
reqAbuseipdb()
