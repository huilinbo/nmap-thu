# Introduction
The project aims to scan and record IP assets of TsingHua University with the help of whois, nmap and MySQL.

## What is whois
The **whois** is a WHOIS client. It is used to communicate with the WHOIS server, which returns information about registered domains, IP addresses, nameservers and so on. You can go to [whois](https://who.is/) for detailed infomation.

## What is nmap
Nmap ("Network Mapper") is a free and open source (license) utility for network discovery and security auditing. You can go to [nmap](https://nmap.org/) for detailed instruction.

# How to

## Find out all THU's IP spaces
`sudo apt install whois`
`python find_thu_ip.py`

## Scan each IP with multiprocess
`pip install python-nmap`
`sudo python scan_ip.py`

## Convert scanned results to MySQL database
`install pymysql`
`python convert_to_mysql.py`

# Thanks
Thanks to Sihong Hong and Jiaming Mu for their great help.