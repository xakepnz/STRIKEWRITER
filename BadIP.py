#!/usr/bin/python
#
# /#######                  /## /###### /#######
#| ##__  ##                | ##|_  ##_/| ##__  ##
#| ##  \ ##  /######   /#######  | ##  | ##  \ ## /######  /##   /##
#| #######  |____  ## /##__  ##  | ##  | #######//##__  ##| ##  | ##
#| ##__  ##  /#######| ##  | ##  | ##  | ##____/| ##  \ ##| ##  | ##
#| ##  \ ## /##__  ##| ##  | ##  | ##  | ##     | ##  | ##| ##  | ##
#| #######/|  #######|  ####### /######| ## /## | #######/|  #######
#|_______/  \_______/ \_______/|______/|__/|__/ | ##____/  \____  ##
#                                               | ##       /##  | ##
#                                               | ##      |  ######/
#                                               |__/       \______/
#[+] Website: https://intellipedia.ch
#[+] Name: BadIP.py
#[+] Author: xakep
#[+] Version: 0.2.0
#[+] Date: November 2016

import datetime
import time
import os
import argparse
import urllib
import urllib2
import requests
import json
import sys
import re
import socket
import logging
from netaddr import IPNetwork, IPAddress

#######################################################################################
#                                Edit these lines                                     #
#######################################################################################
abuseAPIKey = ""                                                                      #
virusTotalAPIKey = ""                                                                 #
#######################################################################################

os.system('clear')
parser = argparse.ArgumentParser(description="You shall not pass.")
parser.add_argument("-i","--input", help="Input IPV4 Address.",required=True)
parser.add_argument("-v","--verbose", help="Verbose Output.",required=False, action="store_true")
args = parser.parse_args()
ip = args.input
verb = args.verbose

if re.match(r'^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$', ip):
    print ("")
    print ("Hint: Use -v or --verbose for a more detailed output.")
    print ("")
else:
    print ("You been drinking?")
    exit (1)

if IPAddress(ip) in IPNetwork("192.168.0.0/16"):
    print ("Take it easy buddy.")
    exit (1)
elif IPAddress(ip) in IPNetwork("10.0.0.0/8"):
    print ("No. Just no.")
    exit (1)
elif IPAddress(ip) in IPNetwork("127.0.0.0/8"):
    print ("First time command line?")
    exit (1)
elif IPAddress(ip) in IPNetwork("172.16.0.0/12"):
    print ("First time Python?")
    exit (1)
else:
    print ("IP address Loaded.")
    print ("")

def update_progress_bar():
    print "\b.",
    sys.stdout.flush()
print "Firing out Probes ",
sys.stdout.flush()

countryCodeOut = requests.get("http://ip-api.com/line/" + ip + "?fields=countryCode")
time.sleep(1)
update_progress_bar()

countryOut = requests.get("http://ip-api.com/line/" + ip + "?fields=country")
time.sleep(1)
update_progress_bar()

orgOut = requests.get("http://ip-api.com/line/" + ip + "?fields=org")
time.sleep(1)
update_progress_bar()

abuseOut = requests.get("https://www.abuseipdb.com/check/" + ip + "/json?key=" + abuseAPIKey + "&days=30")
time.sleep(2)
update_progress_bar()

if abuseOut.content == ("[]"):
    abuseOut = ("No Results.")
else: abuseOut = ("Found!")
time.sleep(1)
update_progress_bar()

virusURL = "https://www.virustotal.com/vtapi/v2/ip-address/report"
virusParameters = {'ip': ip,
              'apikey': virusTotalAPIKey}
virusResponse = urllib.urlopen('%s?%s' % (virusURL, urllib.urlencode(virusParameters))).read()
response_dict = json.loads(virusResponse)
virusPositiveResults = 0
virusTotalResults = 0
time.sleep(1)
update_progress_bar()

try:
    for x in response_dict.get("detected_referrer_samples"):
        virusPositiveResults = virusPositiveResults + x.get("positives")
        virusTotalResults = virusTotalResults + x.get("total")
except TypeError:
    virusOut = ("No Results.")
virusPositiveResults = str(virusPositiveResults)
virusTotalResults = str(virusTotalResults)
time.sleep(2)
update_progress_bar()

threatCrowdOut = requests.get("https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=" + ip)
if threatCrowdOut.content == ('{"response_code":"0"}'):
    threatCrowdOut = ("No Results.")
elif threatCrowdOut.content != ('{"response_code":"0"}'):
    threatCrowdOut = ("Found!")
time.sleep(1)
update_progress_bar()

ransomwareOut = requests.get("https://ransomwaretracker.abuse.ch/ip/" + ip + "/")
if "not found in the Ransomware Tracker" in ransomwareOut.content:
    ransomwareOut = ("No Results.")
elif "table below shows all Ransomware" in ransomwareOut.content:
    ransomwareOut = ("Found!")
time.sleep(1)
update_progress_bar()

cymonOut = requests.get("https://cymon.io/" + ip)
if "IP Not Found" in cymonOut.content:
    cymonOut = ("No Results.")
elif "reported!" in cymonOut.content:
    cymonOut = ("Found!")
time.sleep(1)
update_progress_bar()

ipInDetailOut = requests.get("http://ipindetail.com/ip-lookup/" + ip + ".html")
if "GREEN" in ipInDetailOut.content:
    ipInDetailOut = ("No Results.")
else: ipInDetailOut = ("Found!")
time.sleep(1)
update_progress_bar()

d = datetime.date.today()
month = ("%02d" % (d.month))
day = ("%02d" % (d.day))

def lookup(ip):
    try:
        return socket.gethostbyaddr(ip)
    except socket.herror:
        return None, None, None
name, alias, addresslist = lookup(ip)
while name == None:
   name = ("No Results.")
time.sleep(1)
update_progress_bar()

###################
# Standard Output #
###################
if verb == False:
    print ("")
    print ("")
    print ("Standard Report Generated: " + day + "/" + month + "/" + "2017 - BadIP.py")
    print ("")
    print ("[+] IP: " + ip)
    print ("[+] Country Code: " + countryCodeOut.content.strip("\n"))
    print ("[+] Cymon: " + cymonOut)
    print ("[+] AbuseIPDB: " + abuseOut)
    print ("[+] IPInDetail: " + ipInDetailOut)
    print ("[+] VirusTotal: " + virusOut)
    print ("[+] ThreatCrowd: " + threatCrowdOut)
    print ("[+] Ransomware Tracker: " + ransomwareOut)
    print ("")
##################
# Verbose Output #
##################
else:
    print ("")
    print ("")
    print (" /#######                  /## /###### /#######")
    print ("| ##__  ##                | ##|_  ##_/| ##__  ##")
    print ("| ##  \ ##  /######   /#######  | ##  | ##  \ ## /######  /##   /##")
    print ("| #######  |____  ## /##__  ##  | ##  | #######//##__  ##| ##  | ##")
    print ("| ##__  ##  /#######| ##  | ##  | ##  | ##____/| ##  \ ##| ##  | ##")
    print ("| ##  \ ## /##__  ##| ##  | ##  | ##  | ##     | ##  | ##| ##  | ##")
    print ("| #######/|  #######|  ####### /######| ## /## | #######/|  #######")
    print ("|_______/  \_______/ \_______/|______/|__/|__/ | ##____/  \____  ##")
    print ("                                               | ##       /##  | ##")
    print ("                                               | ##      |  ######/")
    print ("                                               |__/       \______/")
    print ("")
    print ("Report Generated: " + day + "/" + month + "/" + "2017 - BadIP.py")
    print ("")
    print ("IP Lookup: ")
    print ("")
    print ("[+] IP: " + ip)
    print ("[+] Hostname: " + name)
    print ("[+] Country: " + countryOut.content.strip("\n"))
    print ("[+] Provider: " + orgOut.content.strip("\n"))
    print ("")
    print ("Blacklist Information: ")
    print ("")
#    print ("[+] Cymon: " + cymonOut)
    print ("[+] AbuseIPDB: " + abuseOut)
    print ("[+] IPInDetail: " + ipInDetailOut)
    print ("[+] VirusTotal: " + virusOut + " - " + virusPositiveResults + "/" + virusTotalResults + " Total AV detected")
    print ("[+] ThreatCrowd: " + threatCrowdOut)
    print ("[+] Ransomware Tracker: " + ransomwareOut)
    print ("")
