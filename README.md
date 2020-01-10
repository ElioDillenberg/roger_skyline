# Roger_Skyline
Admin Sys Project for school 42

Project done on a VM using Debian 10

# Setup
su (connect as root)

sudo apt-get install -y vim sudo sendmail portsentry ufw apache2

# Add sudo rights to user
usermod -aG sudo edillenb

su edillenb (connect as user with sudo rights)

# Change IP from DHCP generated to static
ip addr (to get ip address) -> 10.12.1.106/16

ip route | grep default (to get gateway address) -> 10.12.254.254

sudo vim /etc/network/interfaces

    source /etc/network/interfaces.d/*
    
    #The loopback Network interface
    auto lo
    iface lo inet loopback
    
    #The primary network interface
    auto enp0s3

sudo vim /etc/network/interfaces/enp0s3

    iface enp0s3 inet static
          address (IP ADDR)
          netmask 255.255.255.252
          gateway (GATEWAY ADDR)

sudo systemctl restart networking

sudo vim /etc/ssh/sshd_config
    
    Port 51188

sudo systemctl restart sshd

# On your local machine, test to connect via ssh to the remote machine: 
ssh edillenb@10.12.1.106 -p 51188

# Now log off and the following is to do on your local machine to enable key auth.
cd ~/.ssh

ssh-copy-id -i id_rsa.pub edillenb@10.12.1.106 -p 51188

# You should now be able to connect through ssh to this user account from your machine without the use of a password
# You can test it:
ssh edillenb@10.12.1.106 -p 51188

# To disable root ssh login and password login:
sudo vim /etc/ssh/sshd_config

    PermitRootLogin no
    
    PubkeyAuthentication yes
    RSAAuthentication yes
    
    PasswordAuthentication no
    
sudo systemctl restart sshd

# Configure FireWall with UFW
sudo ufw enable

sudo ufw default allow outgoing

sudo ufw default deny incoming

sudo ufw default deny forward

sudo ufw limit 51188 (ssh)

sudo ufw allow 80 (http)

sudo ufw allow 443 (https)

source(https://linuxize.com/post/how-to-setup-a-firewall-with-ufw-on-debian-9/)

# Setup DoS protection rules on ports 80 and 443 (ssh port is protected through it's "limit" rule, that would be too restrictive for http and https but ok for ssh) using ufw + IPtables
sudo /etc/ufw/before.rules

right under the line "*filter", add:
    
    :ufw-http - [0:0]
    :ufw-http-logdrop - [0:0]
    
before the line "COMMIT", add:

    ### start DoS Protection ###
    # Enter rule #
    -A ufw-before-input -p tcp --dport 80 -j ufw-http
    -A ufw-before-input -p tcp --dport 443 -j ufw-http

    # Limit connections per Class C
    -A ufw-http -p tcp --syn -m connlimit --connlimit-above 50 --connlimit-mask 24 -j ufw-http-logdrop

    # Limit connections per IP
    -A ufw-http -m state --state NEW -m recent --name conn_per_ip --set
    -A ufw-http -m state --state NEW -m recent --name conn_per_ip --update --seconds 10 --hitcount 20 -j ufw-http-logdrop

    # Limit packets per IP
    -A ufw-http -m recent --name pack_per_ip --set
    -A ufw-http -m recent --name pack_per_ip --update --seconds 1 --hitcount 20 -j ufw-http-logdrop

    # Finally accept
    -A ufw-http -j ACCEPT

    # Log
    -A ufw-http-logdrop -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW HTTP DROP] "
    -A ufw-http-logdrop -j DROP
    ### end ###
 
sudo ufw reload

source (http://lepepe.github.io/sysadmin/2016/01/19/ubuntu-server-ufw.html and http://blog.lavoie.sl/2012/09/protect-webserver-against-dos-attacks.html)
 
# Port scan protection using portsentry
sudo systemctl stop portsentry
 
sudo vim /etc/default/portsentrys
 
        TCP_MODE="atcp"
        UDP_MODE="audp"
        
sudo vim /etc/portsentry/portsentry.conf
 
        BLOCK_UDP="1"
        BLOCK_TCP="1"
        
Also, comment all lines starting with "KILL_ROUTE" besides the following (makes us use iptables for portscan                protection):

        KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"
        
If you want the IP addresses that try to scan you, not to be banned, you can comment the following line:

        KILL_HOSTS_DENY="ALL: $TARGET$ : DENY"
        
Otherwise, anyone who will try to scan you, will be banned through IPtables

sudo systemctl start portsentry

(source: https://fr-wiki.ikoula.com/fr/Se_prot%C3%A9ger_contre_le_scan_de_ports_avec_portsentry)

# Stop the services you do not need
sudo systemctl list-unit-files  (to check all the running services)

sudo systemctl disable rsyslog.service

sudo systemctl disable logrotate.timer

sudo systemctl disable apt-daily-upragde.service

sudo systemctl disable apt-daily.service

# Set up Crontab
sudo vim /etc/cron.d/update_script.sh

        sudo apt-get update -y >> /var/log/update_script.log
        sudo apt-get upgrade -y >> /var/log/update_script.log

sudo chmod 755 /etc/cron.d/update_script.sh

sudo crontab -e

        SHELL=/bin/bash
        PATH=/sbin:/bin:/usr/sbin:/usr/bin

        @reboot sudo /etc/cron.d/update_script.sh
        0 4 * * 6 sudo /etc/cron.d/update_script.sh
 
