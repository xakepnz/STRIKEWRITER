# BadIP.py

<b>[+] Website:</b> https://intellipedia.ch<br />
<b>[+] Name:</b> BadIP.py<br />
<b>[+] Author:</b> xakep<br />
<b>[+] Version:</b> 0.2.0<br />
<b>[+] Date:</b> November 2016<br />
<b>[+] Language:</b> Python 2.*<br />
<b>[+] OS:</b> Linux<br />
<b>[+] Modules:</b> argparse, urllib, urllib2, requests, re, socket, netaddr<br />

<b>Requirements:</b>

You need an API Key from https://abuseipdb.com & https://www.virustotal.com

<b>Help/Usage:</b>

python BadIP.py -h
python BadIP.py -i 196.168.1.0 -v

<b>Description:</b>

This is a simple python script that takes a public IPV4 and searches against a few blacklist websites, to determine a reputation.
There are many sites that already offer this, however incorporating those sites, into a fase CLI tool was the goal here.

<b>Issues:</b>

If it fails, it will mention you need to install the module, as it's not found. - sudo pip install module-name
Small issue with VirusTotal - currently working on this.

<b>To-do:</b>

Add more sites<br />
Add more error checking<br />
Multi thread for faster report<br />
