# Roger_Skyline
Admin Sys Project for school 42

Project done on a VM using Debian 10

# Setup
su (connect as root)

sudo apt-get install -y vim sudo sendmail portsentry ufw fail2ban apache2

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

# Setup DoS protection rules on ports 80 and 443 (ssh port is protected through it's "limit" rule, that would be too restrictive for http and https but ok for ssh)
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
