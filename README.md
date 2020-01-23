# Roger_Skyline
Admin Sys Project for school 42

Project done on a VM using Debian 10

Create a partition of 4.501 GiB for the partition part

# Setup
su (connect as root)

sudo apt-get install -y vim sudo sendmail portsentry apache2

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

# Configure FireWall using Iptables (including DoS/SlowLoris protection)
sudo vim /etc/iptables/script_iptables.sh

        #!/bin/bash

        #This script generates all the iptables rules we need to

        #
        # Flush all iptables (ipv4)
        sudo iptables -F
        sudo iptables -X
        sudo iptables -t nat -F
        sudo iptables -t nat -X
        sudo iptables -t mangle -F
        sudo iptables -t mangle -X
        sudo iptables -P INPUT ACCEPT
        sudo iptables -P FORWARD ACCEPT
        sudo iptables -P OUTPUT ACCEPT
        # Flush all iptables (ipv6)
        sudo ip6tables -F
        sudo ip6tables -X
        sudo ip6tables -t nat -F
        sudo ip6tables -t nat -X
        sudo ip6tables -t mangle -F
        sudo ip6tables -t mangle -X
        sudo ip6tables -P INPUT ACCEPT
        sudo ip6tables -P FORWARD ACCEPT
        sudo ip6tables -P OUTPUT ACCEPT
        ## IPV4

        #
        ### Set policies
        sudo iptables -P INPUT DROP
        sudo iptables -P OUTPUT ACCEPT
        sudo iptables -P FORWARD DROP
        sudo ip6tables -P INPUT DROP
        sudo ip6tables -P OUTPUT DROP
        sudo ip6tables -P FORWARD DROP

        ### Alow established connections
        sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
        sudo iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

        # Allow Loopback
        sudo iptables -t filter -A INPUT -i lo -j ACCEPT
        sudo iptables -t filter -A OUTPUT -o lo -j ACCEPT

        ## Open all port needed (in this case ssh is listening on 51188)
        sudo iptables -t filter -A INPUT -p tcp -m tcp --dport 51188 -j ACCEPT
        sudo iptables -t filter -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
        sudo iptables -t filter -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT

        ##
        #### DOS RULES
        ##

        ### 1: Drop invalid packets ###
        sudo iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
        #
        #### 2: Drop TCP packets that are new and are not SYN ###
        sudo iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
        #
        #### 3: Drop SYN packets with suspicious MSS value ###
        sudo iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
        #
        #### 4: Block packets with bogus TCP flags ###
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
        #
        #### 5: Block spoofed packets ###
        sudo iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
        sudo iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
        sudo iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
        sudo iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
        sudo iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
        sudo iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
        sudo iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
        sudo iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
        #
        #### 6: Drop ICMP (you usually don't need this protocol) ###
        sudo iptables -t mangle -A PREROUTING -p icmp -j DROP
        #
        #### 7: Drop fragments in all chains ###
        #sudo iptables -t mangle -A PREROUTING -m frag -j DROP
        #
        #### 8: Limit connections per source IP ###
        sudo iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset
        #
        #### 9: Limit RST packets ###
        sudo iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
        sudo iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
        #
        #### 10: Limit new TCP connections per second per source IP ###
        sudo iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
        sudo iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP
        #
        #### END OF DOS RULES
        #
        
        ### SLOWLORIS RULE
        sudo iptables -I INPUT -p tcp --syn --dport 443 -m connlimit --connlimit-above 10 -j REJECT --reject-with tcp-reset
        sudo iptables -I INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 10 -j REJECT --reject-with tcp-reset
        sudo iptables -I INPUT -p tcp --syn --dport 51188 -m connlimit --connlimit-above 10 -j REJECT --reject-with tcp-reset

        #### SSH brute-force protection
        sudo iptables -A INPUT -p tcp --dport 51188 -m conntrack --ctstate NEW -m recent --set
        sudo iptables -A INPUT -p tcp --dport 51188 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
        # APPLY RULES

        sudo iptables-save > /etc/iptables/rules.v4
        sudo ip6tables-save > /etc/iptables/rules.v6

        # Restart Netfilter-Persistent service
        sudo systemctl restart netfilter-persistent
 
sudo chmod 755 /etc/iptables/script_iptables.sh
 
sudo /etc/iptables/script_iptables.sh

(source: https://javapipe.com/blog/iptables-ddos-protection/)
 
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

Make sure the following line is also not commented:

        KILL_HOSTS_DENY="ALL: $TARGET$ : DENY"

sudo systemctl start portsentry

sudo systemctl enable portsentry

You can check for banned IPs using the following command:

sudo iptables -L INPUT -v -n | less

If you accidentaly ban your own IP by mistake, don't panick, here is how to fix it:

sudo iptables -D INPUT -s X.X.X.X -j DROP

--> replace X.X.X.X with the IP address you whish to unban

(source: https://fr-wiki.ikoula.com/fr/Se_prot%C3%A9ger_contre_le_scan_de_ports_avec_portsentry)

# Stop the services you do not need
sudo systemctl list-unit-files  (to check all the running services)

sudo systemctl disable rsyslog.service

sudo systemctl disable logrotate.timer

The services here under are the ones you rly need to get rid off, because otherwise they will interfere with your auto_update script on boot used with cron (in a later section)

sudo systemctl stop apt-daily-upgrade.service

sudo systemctl disable apt-daily-upragde.service

sudo systemctl stop apt-daily-upgrade.timer

sudo systemctl disable apt-daily-upragde.timer

sudo systemctl stop apt-daily.timer

sudo systemctl disable apt-daily.timer

sudo systemctl stop apt-daily.service

sudo systemctl disable apt-daily.service

(sources: just check every single active active service and figure out wether you need it or not)

# Set up Crontab
sudo vim /etc/cron.d/update_script.sh

        sudo apt-get update -y >> /var/log/update_script.log
        sudo apt-get upgrade -y >> /var/log/update_script.log

sudo chmod 755 /etc/cron.d/update_script.sh

sudo vim /etc/cron.d/cron_monitor.sh

        #!/bin/bash
        DIFF=$(diff /etc/crontab /etc/cron.d/tmp_cron.log)
        if [ "$DIFF" != "" ]; then
            sudo sendmail root < /etc/cron.d/cron_monitor_mail.txt
            sudo cp /etc/crontab /etc/cron.d/tmp_cron.log
        fi
        
sudo chmod 755 /etc/cron.d/cron_monitor.sh

sudo vim /etc/cron.d/cron_monitor_mail.txt

        Crontab has been modified!

sudo vim /etc/cron.d/tmp_cron.log

sudo chmod 755 /etc/cron.d/tmp_cron.log

sudo touch /var/mail/root

sudo vim /etc/aliases
    
    root:root
    
sudo crontab -e

        @reboot         root    sudo /etc/cron.d/update_script.sh
        0  4    * * 6   root    sudo /etc/cron.d/update_script.sh
        0  0    * * *   root    sudo /etc/cron.d/cron_monitor.sh

(source: https://help.dreamhost.com/hc/en-us/articles/215767047-Creating-a-custom-Cron-Job)

# Web Part (Optional)
Just copy your web app inside the folder : /var/www/html

# Configuration of the SSL Certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt

Just make sure to type in your IP address when prompted for "Common Name"

sudo cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf.bak (backing up the original default-ssl.conf file just to be safe)

sudo vim /etc/apache2/sites-available/default-ssl.conf

        ServerAdmin edillenb@hostname (your email)
        ServerName 10.12.1.106 (your IP address)

        SSLCertificateFile      /etc/ssl/certs/apache-selfsigned.crt
        SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
        
Now redirecting all HTTP traffic to safer HTTPS

sudo vim /etc/apache2/sites-available/000-default.conf

        # Redirecting all traffic to SSL version of the site
        Redirect permanent "/" "https://10.12.1.106/"
        
(make sure that the above has been pasted between the <VirtualHost> tags, the IP address should be your IP address ofc)

sudo a2enmod ssl

sudo a2enmod headers

sudo a2ensite default-ssl

You can now test if everything was done properly:

sudo apache2ctl configtest

sudo systemctl restart apache2

All set!

(source : https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-debian-10 )
