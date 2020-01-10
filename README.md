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

(source: https://linuxize.com/post/how-to-setup-a-firewall-with-ufw-on-debian-9/)

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

(sources: http://lepepe.github.io/sysadmin/2016/01/19/ubuntu-server-ufw.html and http://blog.lavoie.sl/2012/09/protect-webserver-against-dos-attacks.html)
 
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

sudo systemctl start portsentry

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

sudo systemctl disable apt-daily-upragde.service

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
    
sudo vim /etc/crontab

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
