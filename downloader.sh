#!/bin/bash
wget -O /var/www/html/blacklists/ds-block.txt https://www.dshield.org/block.txt
wget -O /var/www/html/blacklists/sh-drop.txt https://www.spamhaus.org/drop/drop.txt
wget -O /var/www/html/blacklists/sh-edrop.txt https://www.spamhaus.org/drop/edrop.txt
wget -O /var/www/html/blacklists/sslipblacklist.txt https://sslbl.abuse.ch/blacklist/sslipblacklist.txt