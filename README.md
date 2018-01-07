# STRIKEWRITER

<b>[+] Author:</b> xakep<br />
<b>[+] Language:</b> Python 2.*<br />
<b>[+] OS:</b> Linux<br />
<b>[+] Modules:</b>argparse, re, requests, socket, time, json, pprint, netaddr<br />

## Requirements:

You need API Keys from https://abuseipdb.com & https://www.virustotal.com & https://ipinfo.io

## Install

```
git clone https://github.com/xakepnz/STRIKEWRITER.git
```

```
cd STRIKEWRITER
```

```
pip install -r requirements.txt
```

```
./strikewriter -i 1.2.3.4
```

## Description:

This is a simple python script that takes a public IPV4 and searches against a few blacklist websites, to determine a reputation.
There are many sites that already offer this, however incorporating those sites, into a fase CLI tool was the goal here.
