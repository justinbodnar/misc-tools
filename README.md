# misc-tools
small scripts and tools

# fresh-lamp-install.sh
installs apache mysql and php on a fresh ubuntu install

# fix-webserver.sh
fixes apache server permissions. recursively targets the /var/www directory

# ./apache-log-security-audit/
analyzes Apache2 logs for evidence of hacking

perhaps followed with:

clamscan -ir --bell --detect-structured=yes  --structured-ssn-format=2 --scan-mail=yes --phishing-sigs=yes --phishing-scan-urls=yes --heuristic-alerts=yes  --heuristic-scan-precedence=no  --scan-pe=yes  --scan-elf=yes  --scan-ole2=yes --scan-pdf=yes --scan-swf=yes  --scan-html=yes  --scan-xmldocs=yes --scan-hwp3=yes --scan-archive=yes --alert-broken=yes  --alert-broken-media=yes --alert-encrypted=yes --alert-encrypted-archive=yes --alert-encrypted-doc=yes  --alert-macros=yes --alert-phishing-ssl=yes  --alert-phishing-cloak=yes  --alert-partition-intersection=yes

