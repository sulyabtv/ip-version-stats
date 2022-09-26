# ip-version-stats
A tool to monitor network traffic and obtain IPv4 vs IPv6 traffic statistics

- Installing on OpenSuse
    - sudo zypper install python3-devel libpcap-devel
    - cd <project_root>
    - mkdir venv
    - python3 -m venv venv
    - bash venv/bin/activate
    - pip3 install -r requirements.txt