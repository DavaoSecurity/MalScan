#!/bin/bash
# script to check linux system for Malware. Tested on Ubuntu 22.04. This script is only the malware scan. Installation is already assumed.
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
HOME=/
SHELL=/bin/bash
echo " "
echo " Make sure you have setup your outgoing SMTP mail server as per the instructions in malscaninstall.sh "
echo " This script will run the malware scans only. Also runs the GUI unhide, which is part of Kali Linux. "
echo " This script assumes you've got all the dependancies installed from malinstall.sh. "
echo " You need to specify your Gmail credentials to allow SMTP traffic when you run malscaninstall.sh. "
echo " "
read -p " What email do you want the results to be sent to ? " umail
echo " "

# investigation
netstat -nalp                            # for unusual processes and open ports
echo " "
read -p " From netstat output given above, what is the PID of the suspicious process ? " pidsus
echo " "
ls -al /proc/$pidsus
echo " "
cp /proc/$pidsus/exe /tmp/recovered_bin > delbin.txt  # to recover any deleted binary
strings /proc/$pidsus/environ > proc.txt              # explore process environment
cat /proc/$pidsus/stack > stackmal.txt                # investigate Linux malware stack
ls -al /proc/$pidsus/fd > filedes.txt                 # show malware open file descriptors
cat /proc/$pidsus/maps > procmaps.tx                  # investigate malware process maps
cat /proc/$pidsus/status pidstats.txt                 # get the PID status
# lynis
lynis audit system | grep malware > lynis.txt
sed -i -e '1iLynis Report\' lynis.txt
sed -i -e '2i***************************************\' lynis.txt
# Check rootkit
sudo chkrootkit | grep "infected" > rootkit.txt
sed -i -e '1iChkrootkit Report\' rootkit.txt
sed -i -e '2i***************************************\' rootkit.txt
# rkhunter
rkhunter -c | grep "infected" > rkhunt.txt
sed -i -e '1iRkhunter Report\' rkhunt.txt
sed -i -e '2i***************************************\' rkhunt.txt
# clamav
freshclam
clamscan -r -i C: | grep "infected" > clamav.txt
sed -i -e '1iClamAV Report\' clamav.txt
sed -i -e '2i***************************************\' clamav.txt
# Linux Malware Detect LMD https://www.tecmint.com/install-linux-malware-detect-lmd-in-rhel-centos-and-fedora/
# edit /usr/local/maldetect/conf.maldet to include your email and scan options
maldet --scan-all /var/www/ > lmd.txt
sed -i -e '1iLinux Malware Detector Report\' lmd.txt
sed -i -e '2i***************************************\' lmd.txt
# maldet --scan-all /var/www/*.zip
# maldet --report 021015-1051.3559
rm -rf /usr/local/maldetect/quarantine/* # remove quarantined files
# maldet --clean SCANID
# set crontab -e
#
# process txt files
cat lynis.txt clamav.txt rootkit.txt rkhunt.txt lmd.txt | sort > malrep.txt
sed -i -e '1iCOMBINED MALWARE REPORT Lynis chkrootkit rkhunter ClamAV LMD\' malrep.txt
sed -i -e '2i****************************************************************\' malrep.txt
# mail
# mail
mail -s "Malware Report" $umail -a malrep.txt
