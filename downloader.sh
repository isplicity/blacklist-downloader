#!/bin/bash
FULLPATH=/var/www/html/blacklists
#FULLPATH=/Users/jamesodell/Documents/git/downloads/
wget -O $FULLPATH/ds-block.txt https://www.dshield.org/block.txt
wget -O $FULLPATH/sh-drop.txt https://www.spamhaus.org/drop/drop.txt
wget -O $FULLPATH/sh-edrop.txt https://www.spamhaus.org/drop/edrop.txt
wget -O $FULLPATH/sslipblacklist.txt https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
sed -n 's/\(.*[^0-9]\|\)\([0-9]\+\.[0-9]\+\.[0-9]\+\.[0]\+\).*\(24\).*/\2\/\3/p' $FULLPATH/ds-block.txt > $FULLPATH/ds-block-filtered.txt
cat $FULLPATH/ds-block-filtered.txt $FULLPATH/sh-drop.txt $FULLPATH/sh-edrop.txt $FULLPATH/sslipblacklist.txt > $FULLPATH/combined.txt

