# OCS-group-43

## ABOUT

This project is an implementation of several attacks intended to be run on a Local Area Network. Using Scapy's framework, it performs ARP poisoning, DNS spoofing and SSL stripping, being partially based on Ettercap's implementation.

## TESTING ENVIRONMENT

How to setup a simple virtual network for testing (router + 2 hosts (victim, attacker)):

1. Download VMware
2. Download Kali .iso for the attacker (link: https://www.kali.org/get-kali/#kali-installer-images)
3. Optionally download ubuntu .iso for victim (link: https://ubuntu.com/download/desktop), can also use kali
4. Download pfsense .iso for the router (link: https://www.pfsense.org/download/), extract the file using a tool like 7-zip
5. Open VMware, create a new virtual network via Edit > virtual network editor > add network. Make the network host-only and disable dhcpp.
6. Create attacker VM and victim VM, make sure to set their network adapter to the created virtual network (can be edited on the left while viewing the powered-off VM)
7. For the router, give it two network adapters: one for the created virtual network and the other for NAT.
8. Configure the router by assigning em0 to LAN and em1 to WAN.

After this the network should work, you can check by pinging other hosts or viewing arp tables by typing arp -n

To test SSL stripping we need a simple webservice that we can connect to. To simulate a user connection to a real webservice outside of our local network we put this webservice in a separate local network.
How to setup a simple HTTPS service for SSL stripping (do this after doing the above steps):

1. Create a new virtual network in VMWare, make it host-only and disable dhcp
2. Add a new network adapter for the newly created network to the router
3. Restart the router. After restarting you should see a new interface (likely named OPT1), assign it to em2.
4. Log into pfsense's admin panel from any host on the original network by typing the router's ip in the address bar (standard settings, username = admin, password = pfsense)
5. Under interfaces > OPT1 (em2), ensure enabled is checked. Set IPv4 configuration type to static IPv4. Under static IPV4 configuration, set the IP address to something like 192.168.2.1/24. Click apply at the bottom of the page. The rest of the settings can be left as-is usually. Make sure 'block private networks' and 'block bogon networks' are disabled.
6. Under services > DHCP server, go to OPT1. Make sure 'Enable DHCP on OPT1 interface' is enabled. Define an address pool range. (eg 192.168.2.100 to 192.168.2.150). Other settings can be left as-is. In the end this should look like what LAN likely already has.
7. Under fireall > nat, make sure mode is set to automatic outbound NAT. Under firewall > rules, copy the all rules from LAN to OPT1. Make sure to check enable interface address/net conversion when copying
8. Create a new VM. Use Ubuntu since this is the easiest when creating a simple webservice. Make sure to set this VM's network adapter to your newly created network.
9. Check that the VM has an IP in OPT1's IP range.

The new ubuntu host should now be active on the new network. To test you can try pinging the new host. Pings should go source > router > new host > router > source
After this we can create a simple HTTPS service on the new Ubuntu host. To do this we will use apache2. The service will use HTTPS by default and will attempt to upgrade users using plain HTTP to HTTPS.

1. Install apache with:
   ```
     sudo apt update
     sudo apt install apache2 -y
   ```
2. Verify apache is running
   ```
     systemctl status apache2
   ```
3. Enable required apache modules
   ```
     sudo a2enmod ssl
     sudo a2enmod rewrite
     sudo a2enmod headers
     sudo systemctl restart apache2
   ```
4. Install PHP. We do this because it's an easy way to make a website that sends a POST request, which is a nice way to demonstrate SSL stripping works
   ```
     sudo apt install php libapache2-mod-php -y
     sudo systemctl restart apache2
   ```
5. Create a self signed certificate. Note that browsers will complain about this certificate but this is acceptable in our case. When prompted for common name, use the webserver's IP
   ```
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/webservice.key -out /etc/ssl/certs/webservice.crt
   ```
6. Enable the default SSL site
   ```
   sudo a2ensite default-ssl
   sudo systemctl reload apache2
   ```
7. Edit the default SSL configuration

   ```
    sudo nano /etc/apache2/sites-available/default-ssl.conf
   ```

   Replace it with:

   ```apache
   <VirtualHost *:443>
    ServerName 192.168.2.10

    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/webservice.crt
    SSLCertificateKeyFile /etc/ssl/private/webservice.key

    <Directory /var/www/html>
      Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/webservice-ssl-error.log
    CustomLog ${APACHE_LOG_DIR}/webservice-ssl-access.log combined
   </VirtualHost>
   ```

8. Add HTTPS redirect (necessary for SSL stripping, without this the tool has no purpose)
   ```
     sudo nano /etc/apache2/sites-available/000-default.conf
   ```
   Replace it with:
   ```apache
   <VirtualHost *:80>
      RewriteEngine On
      RewriteRule ^/(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]
   </VirtualHost>
   ```
9. Reload apache

```
sudo systemctl reload apache2
```

This should already create a functioning webservice which you can visit. For better demonstration of SSL stripping we add a POST request to the page:

1. Create a directory to log POST requests
   ```
     sudo mkdir /var/www/logs
     sudo chown www-data:www-data /var/www/logs
     sudo chmod 750 /var/www/logs
   ```
2. Create a POST handler

   ```
     sudo nano /var/www/html/post.php
   ```

   Add the following code:

   ```php
     <?php
      if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $msg = $_POST['message'] ?? '(empty)';

    file_put_contents(
        "/var/www/logs/post.log",
        date("c") . " " . $_SERVER['REMOTE_ADDR'] . " message=" . $msg . PHP_EOL,
        FILE_APPEND
    );

    echo "<h3>it worked</h3>";
    echo "<a href='/'>send another message</a>";
     } else {
         echo "use the form to write a message";
     }
   ?>
   ```

3. Creat the HTML form

   ```
   sudo nano /var/www/html/index.html
   ```

   Add the following code:

   ````html
   <!DOCTYPE html>
   <html>
     <head>
       <title>message sender</title>
     </head>
     <body>
       <h2>send a message</h2>

       <form method="POST" action="/post.php">
         <label for="message">message</label><br />
         <textarea name="message" rows="4" cols="40"></textarea><br /><br />

         <input type="submit" value="Send" />
       </form>
     </body>
   </html>
   ```
   ````

4. Restart apache

```
  sudo systemctl restart apache2
```

The website should now be available and you should be able to fill in messages. When visiting the website you will probably get a certificate warning which you should just ignore. After a client has sent a message it can be viewed on the server with:

```
  tail -f /var/www/logs/post.log
```

## REQUIREMENTS

### Python

- Python 3.11+
- scapy >= 2.6.1
- psutil >= 7.2.1

### OS

The tool was developed on the latest Kali Linux version (2025.4).

It runs on any Linux-based operating system with netfilter support and `iptables` available. It is expected to be run with root privileges.

## FEATURES

### Network discovery

The tool includes functionalities to discover devices on the local network. It includes a fully automatic discovery process, and an option to let the user choose the network interface and victim devices from a list, or even a fully user configured version which skips the whole scanning process.

### ARP Poisoning

The main feature of the project is an ARP MITM attack, which poisons the ARP caches of the selected devices in order to redirect traffic to our device. The poisoning process is customizable based on the needs of the user.

In MITM mode, the packets received will be forwarded to the destination. The user of this tool can then use further programs to analyze the traffic, such as Wireshark.

There is also a DoS mode, which drops all packets that we receive from the victims.

### DNS Spoofing

Based on the user's configuration, the tool can perform DNS spoofing. Upon receiving a DNS query to a domain from the user's list, the tool drops this packet, and forges a response to it with the fake IP given by the user.

### SSL Stripping

It includes an option to use SSL stripping, which downgrades HTTPS connections of the victim to HTTP in order to read sensitive data.

## CONFIGURATION

The tool can be configured using the `config.toml` file, which includes options to customize each phase of the attack.

### Discovery

- `automatic_discovery` `(bool)`
  Enables or disables automatic device discovery during the discovery phase. During automatic discovery the tool chooses the default interface, and assigns the device whose IP matches the default gateway to group 2, while all other devices get assigned to group 1. The user can fall back to manual device selection.
- `skip_discovery` `(bool)`
  Enables or disables skipping the discovery. When enabled, it uses the hardcoded values below. The tool doesn't perform any verifying on the given hardcoded values, therefore it is the responsibility of the user to enter them correctly.
- `hardcoded_group1` `(List(Pair(str)))`
  Contains the list of victim devices in group 1. A device is represented by an IPv4 address and MAC address pair.
- `hardcoded_group2` `(List(Pair(str)))`
  Contains the list of victim devices in group 2. A device is represented by an IPv4 address and MAC address pair.
- `hardcoded_interface` `(str)`
  Contains the name of the network interface on which the attack will take place.

### ARP Poisoning

- `poison_warm_up` `(int)`
  Sets the delay between the first 5 batches of forged poison packets.
- `poison_delay` `(int)`
  Sets the default delay between each batch of forged poison packets.
- `poison_icmp` `(bool)`
  Enables or disables sending forged ICMP echo requests during the poisoning process.
- `poison_reply` `(bool)`
  Enables or disables sending forged ARP replies during the poisoning process.
- `poison_request` `(bool)`
  Enables or disables sending forged ARP requests during the poisoning process.
- `poison_oneway` `(bool)`
  Enables or disables one-way poisoning. If enabled, only the ARP caches of devices in group 1 will get poisoned.
- `dos_enabled` `(bool)`
  Enables or disables DoS mode. In DoS mode all packets sent from the devices to the attacker get dropped. If disabled, all packets will get forwarded to their destination.

### DNS Spoofing

- `enabled` `(bool)`
  Enables or disables DNS spoofing. When enabled, it intercepts DNS queries from the victims, and forges responses to them if the domain is present in the list below.
- `domains` `(List(Pair(str)))`
  Contains the list of domains to be DNS spoofed. Each entry should contain a pair of the domain name and the fake IP which the victim should be redirected to.

### SSL Stripping

- `enabled` `(bool)`
  Enables or disables SSL stripping.

## HOW TO RUN

The tool should be run with python with root privileges using the command `sudo python main.py`.
