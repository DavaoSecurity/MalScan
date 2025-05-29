#!/bin/bash
# script to check linux system for Malware. Tested on Ubuntu 22.04. This script includes install AND scan procedures.
# by Nathan W Jones nat@davaosecurity.com
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
HOME=/
SHELL=/bin/bash
# install SMTP mail
sudo update
sudo apt install epel-release clamd clamav clamav-daemon -y
# nano /etc/ssmtp/ssmtp.conf and reconfig email addresses to your Gmail SMTP/POP accounts

# lynis
cd /opt/
wget https://downloads.cisofy.com/lynis/lynis-2.6.6.tar.gz
tar xvzf lynis-2.6.6.tar.gz
mv lynis /usr/local/
ln -s /usr/local/lynis/lynis /usr/local/bin/lynis
cd ..
lynis audit system | grep malware > lynis.txt
sed -i -e '1iLynis Report\' lynis.txt
sed -i -e '2i***************************************\' lynis.txt
# Check rootkit
sudo apt install chkrootkit
sudo chkrootkit | grep "infected" > rootkit.txt
sed -i -e '1iChkrootkit Report\' rootkit.txt
sed -i -e '2i***************************************\' rootkit.txt
# rkhunter
sudo apt install rkhunter
rkhunter -c | grep "infected" > rkhunt.txt
sed -i -e '1iRkhunter Report\' rkhunt.txt
sed -i -e '2i***************************************\' rkhunt.txt
# clamav
sudo apt-get install clamav
freshclam
clamscan -r -i C: | grep "infected" > clamav.txt
sed -i -e '1iClamAV Report\' clamav.txt
sed -i -e '2i***************************************\' clamav.txt
# Linux Malware Detect LMD https://www.tecmint.com/install-linux-malware-detect-lmd-in-rhel-centos-and-fedora/
# edit /usr/local/maldetect/conf.maldet to include your email and scan options
wget http://www.rfxn.com/downloads/maldetect-current.tar.gz
tar -xvf maldetect-current.tar.gz
ls -l | grep maldetect
cd maldetect-1.6.4/
ls
./install.sh
cd ..
maldet --scan-all /var/www/ > lmd.txt
sed -i -e '1iLinux Malware Detector Report\' lmd.txt
sed -i -e '2i***************************************\' lmd.txt
#maldet --scan-all /var/www/*.zip
# maldet --report 021015-1051.3559
rm -rf /usr/local/maldetect/quarantine/* # remove quarantined files
# maldet --clean SCANID
# set crontab -e
#
# process txt files
cat lynis.txt clamav.txt rootkit.txt rkhunt.txt lmd.txt | sort > malrep.txt
echo "Look at malrep.txt for results."
