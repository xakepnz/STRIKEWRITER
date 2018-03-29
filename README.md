# STRIKEWRITER

## Description:

This is a simple python script that takes a public IPV4 and searches against a few blacklist websites, to determine a reputation.
There are many sites that already offer this, however incorporating those sites, into a fase CLI tool was the goal here.<br />

<b>[+] Author:</b> xakep<br />
<b>[+] Language:</b> Python 2.*<br />
<b>[+] OS:</b> Linux<br />

![alt text](https://i.imgur.com/97RTcVE.gif "Strikewriter")

## Requirements:

[+] <b>_You need API Keys_</b> from: https://abuseipdb.com & https://www.virustotal.com & https://ipinfo.io<br />
[+] Python dependencies (see below).

## Install:

```
$ git clone https://github.com/xakepnz/STRIKEWRITER.git
```

```
$ cd STRIKEWRITER
```

```
$ pip install -r requirements.txt
```

```
$ chmod +x strikewriter
```

```
$ sudo cp strikewriter /bin/
```

## Usage:
```
$ strikewriter -i 123.123.123.123
```
