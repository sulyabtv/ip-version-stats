# ip-version-stats
A tool to monitor network traffic and obtain IPv4 vs IPv6 traffic statistics

- Installing and Running on OpenWRT (22.03+)
    - Install the following packages (incl. dependencies) using LuCI or opkg: python3 scapy tcpdump ethtool
    - scp sniffer.py and counters.nft to the router
    - ssh to the router
    - Turn off IP tx checksum hardware offloading: ```ethtool -K <intfName> tx-checksumming off```
    - List all options: ```python3 sniffer.py -h```
    - Suggested command: ```python3 sniffer.py -c -i <intfName> -o /tmp &```

- Installing on OpenSuse
    - ```sudo zypper install python3-devel libpcap-devel```
    - ```cd <project_root>```
    - ```mkdir venv```
    - ```python3 -m venv venv```
    - ```source venv/bin/activate```
    - ```pip3 install -r requirements.txt```