# Introduction
Instructions on how to set up `nginx` as a reverse proxy on the public internet providing HTTPS access to local HTTP servers on your LAN and using client certificates to provide security without the need for passwords.

For this you will need a Linux (assumed Ubuntu) machine on the public internet, e.g. the kind provided by [Digital Ocean](https://www.digitalocean.com/), with the `ssh` service running and open to the internet.

**ADVICE: I AM NO SECURITY EXPERT, THIS SETUP IS SUFFICIENTLY SECURE/ROBUST FOR MY PURPOSES, YOU MUST TAKE RESPONSIBILITY FOR YOUR OWN DECISIONS WHERE INTERNET SECURITY IS CONCERNED.**

The steps laid out below are:
  - secure the entities involved,
  - obtain a DNS address,
  - install `nginx`,
  - obtain a server certificate in order to serve HTTPS,
  - create out-bound `ssh` tunnels from HTTP servers that are to be exposed,
  - set up as a local certificate authority,
  - grant browsers access to the HTTP servers by issuing client certificates.

Throughout these instructions:
  - where you see `remote_machine`, replace that with the address of the machine on the public internet (domain name when available, otherwise IP address),
  - where you see `name@address`, replace that with an e-mail address that you have access to.

# Secure The Machine That Is On The Public internet
Before you start, make sure that the machine on the public internet is secured.  For instance, only one port, usually port 22 (so that you can get at it with `ssh`) should be exposed through its firewall.

- If you are starting a new machine from scratch, while logged in as `root`, create a user and switch off `root` log-in as follows, noting that it is worth using a particularly good/unique password for this user since it will be relatively powerful:

  ```
  adduser username_main
  adduser username_main sudo
  passwd -l root
  ```

  ...where `username_main` is replaced with your chosen user name.

- Also create another user, named something like `username_tunnel` (not in the `sudo`ers list for security).

  ```
  adduser username_tunnel
  ```

- Log out and back in again as `username_main`.

- On the client machines that you want to have `ssh` access to the machine on the public internet (including those running HTTP servers that you want to make available externally), create SSH keys by entering:

  ```
  ssh-keygen
  ```

  ...and following the prompts; when asked if you want to protect the private key with a password, do so if the `ssh` access from that machine will be a "normal" interactive SSH terminal but not if you will be making an HTTP server available (since the SSH daemon you will be running in that case can't type).  IMPORTANT: the private keys, the files with no file extension, MUST NEVER LEAVE THESE CLIENT MACHINES.

  Note: if the `.ssh` directory didn't previously exist you may have to give it the correct permissions with `sudo chmod 700 ~/.ssh` before it can be accessed by `ssh` when running as a service; there is no harm in doing this once anyway.

- While you still have password-access via `ssh` to the machine on the public internet, you can upload the `.pub` keys generated on the client machines with:

  ```
  ssh-copy-id username@remote_machine
  ```

  ...where `username` is `username_main` as created above or, for machines that will expose HTTP servers, `username_tunnel`.  Accept the identity of the host if prompted to do so.

- Once you have done this for all of the client machines, switch off password-based SSH access on the machine that is on the public internet by editing the file `/etc/ssh/sshd_config` to change `#PasswordAuthentication yes` to `PasswordAuthentication no`, i.e. remove the `#` and change `yes` to `no`.  Enter `sudo systemctl daemon-reload` to load the new configuration then restart the SSH server with `sudo systemctl restart ssh` and make sure that this has worked by trying to `ssh` from a client machine with user name and password: if using a password still works, check that there isn't an override configuration file in the directory `/etc/ssh/sshd_config.d` that is switching password-based SSH access on again.

  Note: if you need to add a new `ssh` key _after_ you have switched-off password-based `ssh` access you will need to use a client machine that _is_ able to access the machine on the public internet to manually add the contents of each of the `.pub` files (each will be a single line) to the file `.ssh/authorized_keys`, either off `username_main`'s home directory or off `username_tunnel`'s home directory; cutting and pasting it will be fine, it is text.

  Note: if you want to use `PuTTY` on a client machine you will need to convert the private key into a `.ppk` file using `PuTTYgen` on that machine, see advice on the internet for how to do this.

- Check if you have an active firewall with `sudo ufw status`: it is up to you whether you use one or not.  In my case, I had a single machine on the public internet and so there was no value in enabling `ufw`, I could just control access via the network firewall of the same machine.  If you _do_ choose to activate `ufw`, make sure that, when the instructions below indicate that a port should be opened for incoming TCP connections, you do so in `ufw` as well as on the network firewall.

- Decide on the port you will use for `ssh` access: you may leave it as port 22 or you may choose a different port: open that port for in-bound TCP access on the network firewall (and in `ufw` if it is active), edit `/etc/ssh/sshd_config`, remove the `#` from the line `#port 22`, change the port number, `sudo systemctl daemon-reload` to load the new configuration and then restart the `ssh` service with `sudo systemctl restart ssh`; if your able to `ssh` back in again, remove in-bound TCP access on port 22.  You will then need to add `-p <portnumber>` to all of the `ssh` and `autossh` command-lines below.

# Secure Your HTTP Servers
We will only be exposing the HTTP servers to browsers that have installed a client certificate which we have consciously chosen to provide but it is still worth making sure that the HTTP servers are as secure as possible in case the client certificate and its key is somehow spread to a bad actor.  Some [tips for Apache2](https://help.dreamhost.com/hc/en-us/articles/226327268-The-most-important-steps-to-take-to-make-an-Apache-server-more-secure):

- make sure that Apache is running as the `www-data` user (check the variable `APACHE_RUN_USER` in `/etc/apache2/envvars`); Apache will have created this user on installation to give it the minimum permissions required to do its work,
- edit `/etc/apache2/conf-available/security.conf` and set `ServerTokens` to `Prod`; this will minmise the OS/version details included in HTTP headers,
- make sure that, in `/etc/apache2/apache2.conf` and in your `/etc/apache2/sites-available/000-default.conf` file, `AllowOverride` is set to `None` to stop `.ht-access` files overriding permissions,
- edit `/etc/apache2/apache2.conf` to add `RequestReadTimeout header=10-20,MinRate=500 body=20,MinRate=500`; this will prevent a "slowloris" denial of service attack,
- don't forget to issue `sudo service apache2 reload` after making any changes.

# DNS Address
By whatever means at your disposal, give the machine that is on the public internet a DNS address.  For instance, you might use a service such as [noip](https://www.noip.com/) as follows.

- Create a [noip](https://www.noip.com/) DNS entry of type DNS Host and then install the dynamic update client on the machine that is on the public internet:

  ```
  wget --content-disposition https://www.noip.com/download/linux/latest
  tar xf noip-duc_3.3.0.tar.gz
  cd noip-duc_3.3.0/binaries
  sudo apt install ./noip-duc_3.3.0_amd64.deb
  ```

- Back in your [noip](https://www.noip.com/) account, generate a "DDNS Key" for this DDNS entry, which will be a user name and password pair; make a note of the password (which will not be shown again) then confirm that the key works by running:

  ```
  noip-duc -g all.ddnskey.com -u username-of-DDNS-key -p password-of-DDNS-key
  ```

  You should see something like:

  ```
  Attempting to get IP with method Dns(No-IP Anycast DNS Tools)
  got new ip; current=xxx.xxx.xxx.xxx, previous=0.0.0.0
  update successful; current=xxx.xxx.xxx.xxx, previous=0.0.0.0
  checking ip again in 5m
  ```

  ...and in your [noip](https://www.noip.com/) account the dynamic DNS entry should show the IP address of the machine on the public internet.

- Stop `noip-duc` with CTRL-C and, to make it run at boot, create a configuration file named `/etc/default/noip-duc` with the following contents:

  ```
  NOIP_USERNAME=username-of-DDNS-key
  NOIP_PASSWORD=password-of-DDNS-key
  NOIP_HOSTNAMES=all.ddnskey.com
  ```

  ...then install the file `~/noip-duc_3.3.0/debian/service` and have it run at boot as follows:

  ```
  sudo cp ~/noip-duc_3.3.0/debian/service /etc/systemd/system/noip-duc.service
  sudo systemctl start noip-duc
  sudo systemctl enable noip-duc
  ```

- Reboot and check that:

  ```
  sudo systemctl status noip-duc
  ```

  ...shows an active service.

# `nginx`
All of the actions that follow are carried out on the machine that is on the public internet.

- Install `nginx` with:

  ```
  sudo apt install nginx
  ```

- Open port 80 on the network firewall of the machine that is on the public internet (and in `ufw` on that machine, if active) for incoming TCP connections.

- Open a browser on your local machine and navigate to `http://remote_machine`; make sure that the browser stays with `http://` and doesn't switch to `https://` on you.  You should see a "Welcome to nginx!" page.  If the connection times out, try again with the IP address of the machine on the public internet: if that works then there is something up with your DNS arrangements.  If even an IP address doesn't work, make sure you have opened port 80 for incoming TCP connections on the network firewall of the machine on the public internet, and in `ufw` on that machine if it is active.

- Create a configuration location for the domain `remote_machine` as follows:

  ```
  sudo mkdir -p /var/www/remote_machine/html
  sudo chown -R $USER:$USER /var/www/remote_machine/html
  ```

- Provide a default page in this directory by creating a file `/var/www/remote_machine/html/index.html` with contents:

  ```
  <html>
      <head>
          <title>Welcome to remote_machine</title>
      </head>
      <body>
          <h1>server block is working</h1>
      </body>
  </html>
  ```

- Create the directory `/etc/nginx/sites-available/remote_machine`:

  ```
  sudo mkdir /etc/nginx/sites-available/remote_machine
  ```

  Note: we're adding a directory here, rather than just a file, so that we can have a common configuration file shared between listeners on multiple ports/mappings.

- Create a common configuration file in this directory named `common.cfg` with contents:

  ```
          root /var/www/remote_machine/html;
          index index.html index.htm index.nginx-debian.html;

          server_name remote_machine www.remote_machine;
  ```

- Provide an `nginx` "server block" for the default port on the domain by creating a file in this directory named `remote_machine_port_default` with contents:

  ```
  server {
          listen      80;
          listen [::]:80;

          include /etc/nginx/sites-available/remote_machine/common.cfg;

          location / {
                  try_files $uri $uri/ =404;
          }
  }
  ```

- Enable this server block with:

  ```
  sudo ln -s /etc/nginx/sites-available/remote_machine/remote_machine_port_default /etc/nginx/sites-enabled/
  ```

- For optimisation reasons, edit the file `/etc/nginx/nginx.conf` and remove the `#` from the start of the line `server_names_hash_bucket_size blah`.

- Restart `nginx` with:

  ```
  sudo systemctl restart nginx
  ```

- Open a browser on your local machine and navigate to `http://remote_machine`; you should now see "server block is working" rather than the original `nginx` page.  Should you need to fix anything, don't forget to issue `sudo systemctl restart nginx` to load any changes.

# HTTPS
How you go about obtaining a signed certificate for `remote_machine`, so that you can use HTTPS, will depend on how you obtained the domain name.  The most common way is to use Certbot and Let's Encrypt; that can be done in concert with `nginx` as described in the "Certbot" section below.  However, note that if you are using a free [noip](https://www.noip.com/) redirect you likely will have to intervene manually to refresh the certificate every 3 months.

If you have a [noip](https://www.noip.com/) paid account, that comes with "No-IP Vital Encrypt DV" which must be manually requested but is valid for one year.

Other mechanisms may apply if you obtained your domain name another way.

All of the actions that follow are carried out in the home directory of `username_main` on the machine that is on the public internet.

## Using No-IP Vital Encrypt DV
Note: this is done in a few steps and with an `openssl` configuration file so as to include both `www.remote_machine` and `remote_machine` in the certificate signing request and to allow for easier manual renewal.

- Create a private key with:

  ```
  openssl genrsa -out remote_machine.private_key.pem 2048
  ```

- Keep `remote_machine.private_key.pem` safe; do not reveal it to anyone and do not let it leave the machine.  As a little extra security, make it readable only by `root` with:

  ```
  chmod 600 remote_machine.private_key.pem
  sudo chown root:root remote_machine.private_key.pem
  ```

  Note: if you want to run `nginx -t` afterwards, to check the syntax of your `nginx` configuration, do it with `sudo` so that `nginx -t` is able to read the key file.

- Create a file named `remote_machine.cnf` with the following contents (not forgetting to replace `remote_machine` with the domain name and modifying any other of the `req_distinguished_name` parameters as appropriate):

  ```
  [ req ]
  default_bits = 2048
  encrypt_key = no
  default_md = sha256
  utf8 = yes
  string_mask = utf8only
  prompt = no
  distinguished_name = req_distinguished_name

  [ req_distinguished_name ]
  countryName = GB
  stateOrProvinceName = Essex
  localityName = Saffron Walden
  commonName = remote_machine

  [ req_ext ]
  subjectAltName = @alt_names

  [ alt_names ]
  DNS.1 = remote_machine
  DNS.2 = www.remote_machine
  ```

- Create a certificate signing request using the private key and this configuration file with:

  ```
  sudo openssl req -new -sha256 -out csr.pem -key remote_machine.private_key.pem -config remote_machine.cnf
  ```

- Press the [+ Create](https://my.noip.com/my-services/ssl-certificates) button on the [noip](https://www.noip.com/) Vital Encrypt DV page and paste in the contents of `csr.pem`.

- In less than an hour the signed certificate should appear on the same page: download it (the full version) into the home directory of `username_main` on the machine that is on the public internet.

## Using Certbot
- Certbot is "snappy", so make sure `snap` is installed and up to date with:

  ```
  sudo snap install core; sudo snap refresh core
  ```

- Make sure that there is no "non-snap" version of Cerbot installed with:

  ```
  sudo apt remove certbot
  ```

- Install Certbot with:

  ```
  sudo snap install --classic certbot
  ```

- If you have DNS A and AAA records, obtain a private key and get that signed by a CA (Let's Encrypt) by running Certbot's `nginx` plugin with:

  ```
  sudo certbot --nginx -d remote_machine -d www.remote_machine
  ```

  ...giving an e-mail address that terminates with you when prompted.

- If you have only TXT records and are unable to script updating a TXT record (e.g. [noip](https://www.noip.com/)):

  - Log-in to [noip](https://www.noip.com/) or wherever, and be ready to add a new TXT record.

  - Obtain a private key and get that signed by a CA (Let's Encrypt) by running Certbot with:

    ```
    sudo certbot -v /etc/letsencrypt:/etc/letsencrypt -v /var/lib/letsencrypt:/var/lib/letsencrypt certbot/certbot certonly --manual --debug-challenges --preferred-challenges dns -d remote_machine -d www.remote_machine
    ```

    ...giving an e-mail address that terminates with you and `remote_machine` as the domain if prompted.

  - You will be asked to add a TXT record to the DNS record, inside [noip](https://www.noip.com/) or wherever, with an `_acme-challenge` sub-domain (i.e. prefix) and with the value being a random text string that Let's Encrypt will check.  Do this and confirm to `CertBot` that you have done so.

- The private key and signed certificate will have been placed into `/etc/letsencrypt/live/remote_machine`.

- You will be sent an e-mail a few weeks before the certificate (3 months validity) expires; if you were able to create the certificate in the first place without manual intervention, you may renew it automatically by scripting the following command to run, say, once a day on the machine that is on the public internet:

  ```
  sudo certbot -v /etc/letsencrypt:/etc/letsencrypt -v /var/lib/letsencrypt:/var/lib/letsencrypt -p 80:80 certbot/certbot renew
  ```

- Note: once `nginx` is running, after updating certificates it will need to be reloaded with `sudo systemctl restart nginx` to start using them.

## Configuring `nginx` For HTTPS
Now that we have a certificate for `remote_machine` we can configure `nginx` to serve HTTPS requests:

- Open port 443 on the network firewall of the machine that is on the public internet (and in `ufw` on that machine, if active) for incoming TCP connections.

- Modify the file `/etc/nginx/sites-available/remote_machine/remote_machine_port_default` to add the following below the existing two `listen` lines:

  ```
          listen       443 ssl;
          listen  [::]:443 ssl;
  ```

- Modify the file `/etc/nginx/sites-available/remote_machine/common.cfg` to add the following at the top:

  ```
          ssl_certificate        /absolute/path/to/signed/certificate.pem;
          ssl_certificate_key    /absolute/path/to/private/key.pem;
  ```

- Restart `nginx`:

  ```
  sudo systemctl restart nginx
  ```

- Open a browser on your local machine and navigate to `https://remote_machine` (i.e. now HTTPS instead of HTTP); you should see "server block is working" and the browser should show that the connection is now a secure one.

# Tunneling Out From Your HTTP Servers

## Background
To expose a local service we use an SSH reverse tunnel: effectively the machine on the LAN running the HTTP server that you want to expose opens an SSH tunnel to the machine that is on the public internet.  Rather than opening an interactive SSH session, the SSH server running on the machine on the public internet is told to forward any packets it receives on a given port down the SSH tunnel to the local machine.  The TCP connection carrying the SSH tunnel is outgoing and so there is no need to make a hole in your LAN's firewall/network or configure port forwarding on your router.  Access to the tunnnel is protected through the use of `nginx` and client certificates in the next step.

Linux does not permit a machine to forward ports lower in number than 1024, that's just the way it is.  Say you wanted to use port 8888 for this purpose; assuming the HTTP server on the local machine is running on port 80, you would execute the following command on the local machine:

  ```
  ssh -N -R 8888:localhost:80 username_tunnel@remote_machine
  ```

This tells the SSH server on `remote_machine` (the machine on the public internet) to send any packets headed for port 8888 to the machine where you ran the above command, port 80. `-N` means don't do an interactive login.

Pick a different port for each of the local HTTP servers you want to expose (or take advantage of `nginx`'s ability to re-map paths) and Bob is your mother's brother.

## Implementation

### Machine On The Public Internet
- Edit the file `/etc/ssh/sshd_config` and add a section at the end:

  ```
  Match User username_tunnel
             AllowTcpForwarding remote
             GatewayPorts yes
             ClientAliveInterval 30
             ClientAliveCountMax 2
             ForceCommand /bin/false
  ```

- Restart the SSH server with `sudo systemctl restart ssh` after making the changes.

  Note: this means that the client machines that have lodged their SSH keys with `username_tunnel` will not have normal, interactive, SSH access (this is what `ForceCommand /bin/false` does); if you need that you might want to do it with an additional SSH key-pair that has a password-protected private key, lodging the contents of the corresponding public key in the file `.ssh/authorized_keys` under the home directory of `username_main`.

- To test that this has worked, run `netstat -tulpn` on the machine on the public internet to get a baseline, then on one of the local machines that should be able to tunnel, run:

  ```
  ssh -N -R 8888:localhost:80 username_tunnel@remote_machine
  ```

- Now run `netstat -tulpn` on the machine on the public internet again and you should see at least one additional line:

  ```
  tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      -
  ```

  You may see another additional line for IPV6.  Note that nothing has been exposed yet since port 8888 will not have been opened for incoming connections on the firewall of the machine on the public internet.

- It is worth performing this procedure the first time you attempt to access the machine on the public internet with `ssh` in case you need to manually accept the signature of the remote machine.

  Note: use the domain name established above for `remote_machine` to avoid any future complications if the IP address changes.  Note also that an IP address and a domain name for the same remote machine are treated separately by the `ssh` signature-checker, so if you use both you will have to manually accept the signature on the first try for both.

### Local Machine With HTTP Server That You Want To Expose
Do the following for each of the local machines running an HTTP server that you want to expose.

- Rather than just running `ssh` as a command-line, or even as a `systemd` service, the favoured approach seems to be to install [autossh](https://www.harding.motd.ca/autossh/) as follows:

  ```
  wget -c https://www.harding.motd.ca/autossh/autossh-1.4g.tgz
  gunzip -c autossh-1.4g.tgz | tar xvf -
  cd autossh-1.4g
  sudo apt install gcc make
  ./configure
  make
  sudo make install
  ```

- Run `autossh` once, manually, as `sudo` with something like:

  ```
  sudo /usr/local/bin/autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -N -R 8888:localhost:80 username_tunnel@remote_machine -i path/to/ssh_private_key
  ```

  ...replacing `8888` with your chosen port number; the `ssh_private_key` is the one you created on this machine right at the start, when securing things.  This will cause the server to send "alive" messages every 30 seconds and for the tunnel to be restarted after three such messages have gone missing.

- Assuming that worked, CTRL-C and then start `autossh` with a `systemd` file named something like `/etc/systemd/system/tunnel-http.service` containing something like the following:

  ```
  [Unit]
  Description=Persistent SSH Tunnel for HTTP
  After=network.target

  [Service]
  Restart=on-failure
  RestartSec=5
  Environment=AUTOSSH_GATETIME=0
  ExecStart=/usr/local/bin/autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -N -R 8888:localhost:80 username_tunnel@remote_machine -i path/to/ssh_private_key
  ExecStop= /usr/bin/killall autossh

  [Install]
  WantedBy=multi-user.target
  ```

- Run:

  ```
  sudo systemctl start tunnel-http
  ```

- Reboot and check that:

  ```
  sudo systemctl status tunnel-http
  ```

  ...shows an active service; you might also want to run `netstat -tulpn` on the machine on the public internet and check that its `ssh` server is now listening on the port you have chosen.  Assuming all is good, enable the service to start at boot with:

  ```
  sudo systemctl enable tunnel-http.service
  ```

- Reboot and check again that all is good.

  Remember that NOTHING has yet been exposed as the ports on the network firewall of the machine on the public internet are not open for incoming TCP connections.

# Setting Up As A Certificate Authority
Before connecting the tunnels to the outside world, an authorisation mechanism is required.  For this we use client certificates: a browser is requested to provide its certificate by the HTTPS server (in this case `nginx`) and no pages are served unless the certificate checks out.  In order to issue client certificates we need to set up as a local certificate authority.

Note: the keys/certificates etc. used here are entirely separate from the PKI, or any certificates generated by LetsEncrypt/Certbot etc., don't mix the two.  Also, the naming pattern used by Cerbot (more correct in my view), in which the file extension `.pem` designates the format of the file, is replaced here by what appears to be the more usual format for SSL stuff, which is that certificates end with `.crt`, keys with `.key` and certificate signing requests with `.csr`; all are PEM format anyway.

Perform the following actions on the machine that is on the public internet.

- Set SSL up for ease of certificate management by doing:

  ```
  sudo mkdir /etc/ssl/CA
  sudo mkdir /etc/ssl/csr
  sudo mkdir /etc/ssl/newcerts
  sudo sh -c "echo '01' > /etc/ssl/CA/serial"
  sudo sh -c "echo '01' > /etc/ssl/CA/crlnumber"
  sudo touch /etc/ssl/CA/index.txt
  sudo mkdir /etc/pki/tls
  ```

- Create `/etc/pki/tls/openssl.cnf` and populate it with the following, not forgetting to replace `remote_machine` with the domain name of the machine on the public internet:

  ```
  [default]
  dir         = /etc/ssl                                     # Where everything SSLish kept
  default_md  = sha256                                       # MD to use

  [ca]
  default_ca  = default_ca                                   # The default CA section

  [default_ca]
  database         = $dir/CA/index.txt                       # database index file.
  serial           = $dir/CA/serial                          # The current serial number
  crlnumber        = $dir/CA/crlnumber                       # the current crl number
  crl              = $dir/CA/ca.crl                          # The current CRL
  new_certs_dir    = $dir/newcerts                           # Where to put newly generated certificates
  certificate      = $dir/certs/remote_machine.ca.crt        # The server certificate
  private_key      = $dir/private/ca.key                     # The private key
  policy           = policy_match                            # Default naming policy
  default_days     = 365                                     # How long to certify for
  default_crl_days = 36500                                   # how long before next CRL

  [policy_match]
  countryName             = optional
  stateOrProvinceName     = optional
  organizationName        = supplied
  organizationalUnitName  = optional
  commonName              = optional
  emailAddress            = supplied
  ```

- Generate a password-protected master key for your Certificate Authority:

  ```
  sudo openssl genpkey -algorithm RSA -out /etc/ssl/private/ca.key -aes256
  ```

- Using this, create a CA certificate for the server to sign things with, valid for 10 years:

  ```
  sudo openssl req -new -x509 -days 3650 -key /etc/ssl/private/ca.key -out /etc/ssl/certs/remote_machine.ca.crt
  ```

  ...entering `.` to leave fields empty except for:
  - `Common Name`, which should be populated with the value of `remote_machine`,
  - `Email Address`, which should be populated with an e-mail address that terminates with you.

- Create an initial (empty) Certificate Revocation List with:

  ```
  sudo openssl ca -gencrl -keyfile /etc/ssl/private/ca.key -cert /etc/ssl/certs/remote_machine.ca.crt -out /etc/ssl/CA/ca.crl -config /etc/pki/tls/openssl.cnf
  ```

## Configuring `nginx` For Client Authentication
Now that we have the ability to generate client certificates, we can configure `nginx` to require them:

- Modify the file `/etc/nginx/sites-available/remote_machine/common.cfg` to add the following below the existing `ssl_certificate_key` line:

  ```
          ssl_client_certificate /etc/ssl/certs/remote_machine.ca.crt;
          ssl_crl                /etc/ssl/CA/ca.crl;
          ssl_verify_client on;
  ```

- Restart `nginx`:

  ```
  sudo systemctl restart nginx
  ```

- Open a browser on your local machine and navigate to `https://remote_machine`; you should now see "400 Bad Request: no required SSL certificate was sent".

# Giving Access
The steps required for setup of each client that wishes to access `https://remote_machine` are set out below.  Generation of the key/CSR may be done either by the user (typically a Linux user will know how to do this) or you may do it yourself (which would be necessary for mobile phones and might be an easier option for Windows users since then there is no need to install OpenSSL on their machine).  Getting the user to do it is preferred as that way their private key never leaves their device.

## "User Generates Private Key" Method
Use this method if the user answers yes to the question "are you OK to run OpenSSL to generate private keys and signing requests?"; if so, make sure that, when they send you their certificate signing request (see below), they populate the `Organisation Name` with the name of their device and the `E-mail Address` field with their e-mail address.

### Generation
- Ask the user to install [OpenSSL](https://www.ibm.com/docs/en/ts4500-tape-library?topic=openssl-installing) on the device they wish to access the automated test system from, if they've not done so already,

- Ask the user to generate a private key that identifies them on that device with the command below (the key should be password protected):

  ```
  sudo openssl genrsa -des3 -out remote_machine.key 4096
  ```

- Tell them to keep the `remote_machine.key` file somewhere safe and NEVER to reveal it to anyone.

- Ask the user to generate a certificate signing request for this private key with the command below and then e-mail the generated `.csr` file to you for processing; they should replace `devicename` with a string representing their device (e.g. for me it would be `RobLaptop`) and, so that it is possible to manage things, they should enter the same string in the `Organisation Name` field of the CSR and they should populate the `E-mail Address` field correctly in the CSR (everything else may be left blank by pressing `.` and then `<enter>`):

  ```
  sudo openssl req -new -key remote_machine.key -out remote_machine.devicename.csr
  ```

- When you receive the `.csr` file, provided it is **definitely** from the expected user, it should be stored on the machine that is on the public internet in the directory `/etc/ssl/csr`, then a signed certificate should be generated from it on that machine with something like:

  ```
  sudo openssl ca -in /etc/ssl/csr/remote_machine.devicename.csr -config /etc/pki/tls/openssl.cnf
  ```

  Note: keeping the `.csr` file in this way means that a new certificate can be generated from the same CSR file when the previous one expires in 365 days.

- When done, a new file, e.g. `01.pem`, should appear in the `/etc/ssl/newcerts/` directory: e-mail this file, renamed to `remote_machine.devicename.crt`, **PLUS** `remote_machine.ca.crt` back to the user; it doesn't matter if these files go astray, they will only work for the user that has the private key.

- Note: to revoke an existing certificate, `cat /etc/ssl/CA/index.txt` to look up which `xx.pem` file was created for it and then issue the following commands, replacing `xx.pem` with the relevant file:

  ```
  sudo openssl ca -revoke /etc/ssl/newcerts/xx.pem
  sudo openssl ca -gencrl -keyfile /etc/ssl/private/ca.key -cert /etc/ssl/certs/remote_machine.ca.crt -out /etc/ssl/CA/ca.crl -config /etc/pki/tls/openssl.cnf
  sudo systemctl restart nginx
  ```

- The default OpenSSL configuration file will not allow you to generate a new certificate for one which already exists in the index.  If a client certificate is about to expire and you want to generate a new one to send to the user _before_ the one they have expires, you will need to edit `/etc/ssl/CA/index.txt.attr` (create it if it doesn't exist) to have the line `unique_subject = no` in it.

- If a client certificate has expired, run the following command:

  ```
  sudo openssl ca -updatedb -config /etc/pki/tls/openssl.cnf
  ```

  This will update `/etc/ssl/CA/index.txt` so that the certificate is marked as expired (with an `E` in the first column).  If you wish, you may then you generate a new certificate from the same `.csr` file using exactly the same command-line as you used to create it in the first place.

### Installation
These steps are carried out by the user on the device where they generated their private key.

- Create a `.pfx` file from the locally-generated `remote_machine.key`, the received signed certificate and the received Certificate Authority (you will be asked for the password for the `.key` file and you **must** then provide a password for the `.pfx` file, since otherwise the `.key` will be in plain text again inside the `.pfx` file) with something like:

  ```
  openssl pkcs12 -export -out remote_machine.devicename.pfx -inkey remote_machine.key -in remote_machine.devicename.crt -certfile remote_machine.ca.crt
  ```

- If the user is running Linux, they should install this bundle in Firefox by going to `Settings`, searching for `Certificates`, pressing `View Certificates`, selecting the `Your Certificates` tab, then `Import` and selecting the `.pfx` file.  Then restart FireFox and try again.

- If the user is running Windows they should double-click the `.pfx` file, select `Current User` in the dialog box that pops up, confirm the file to import, enter the password for the `.pfx` file, allow the wizard to decide where to put the certificates and press `OK` to add the lot.  They _must_ then delete the `.pfx` file from any place it might have been stored (disk, e-mail with attachment, etc.)

- If the user has an Android phone they should go to  `Settings` > `Security and privacy` >  `More security and privacy` > `Encryption and credentials` > `Install a certificate` > `VPN and app user certificate`, select the `.pfx` file, enter the password, maybe give it a human-readable name, and install it.  They _must_ then delete the `.pfx` file from any place it might have been stored (disk, e-mail with attachment, etc.)

- Open a browser and make an HTTPS connection to the `https://remote_machine`; it should prompt for the certificate to use: chose the one it offers, which will be the one just installed, and then the proper HTML page should appear.

- Troubleshooting: if it does not you might take a Wireshark log on your local machine while doing the above and look in the SSL handshake for (a) the server sending a Certificate Request (the Distinguished Names it is asking for should be those of the CA certificate) and (b) the client responding with Certificate: is it of non-zero length and, if so, does the Public Key string match the one in the signed certificate that you installed?

## "You Generate Private Key"  Method
Use this method if the user is not able to generate a private key on their device.

- Ask them to e-mail their `devicename` to you.

- Generate a password-protected private key for that user, a certificate signing request to go with it, and then generate the actual certificate, with something like (filling in `devicename` in the `Organisation Name` field and their e-mail address in the `E-mail Address` field of the certificate signing request, leaving the rest empty by just entering `.`):

  ```
  openssl genrsa -des3 -out devicename.key
  openssl req -new -key devicename.key -out remote_machine.devicename.csr
  ```

- Handle the signing request as described in the section above (store it on the machine that is on the public internet in the directory `/etc/ssl/csr` and sign it, etc.).

- Create a password-protected PFX file which will include the private key you generated for them, the signed certificate for it and the public Certificate Authority with:

  ```
  openssl pkcs12 -export -out remote_machine.devicename.pfx -inkey devicename.key -in remote_machine.devicename.crt -certfile remote_machine.ca.crt
  ```

- Now you can delete the file `devicename.key`; when you need to renew the certificate you will need to start this process off again, generating a new private key for this user.

- Send the user the `.pfx` file and, over a separate channel, let them know the password that goes with it; unlike the case where the user generated the private key, this file should be destroyed ASAP after installation (e.g. in all outgoing and incoming e-mails) as it is possible for someone to guess or brute-force the password and obtain the private key from it.

- Continue from [Installation](#installation) above, but using the `.pfx` file (and separate password) received, rather than the one locally generated.

# Exposing Your HTTP Servers
You now have everything in place to expose a local HTTP server externally, securely.  All that remains is to make the connection between `nginx` and the ends of the HTTP tunnels.  The simplest way to do this, rather than opening multiple ports, would be to redirect a URL path within `nginx`: for instance triggering on the `some/path/` from `https://remote_machine/some/path/` and sending such requests to, for instance, port 8888.  However, it might be that your HTTP server includes links that assume the site is at the root: for instance, a page it returns might include a link to `/resoure.png` which, when requested, will of course fail as the request the browser will make will be to `https://remote_machine/resoure.png`, rather than `https://remote_machine/some/path/resoure.png`; the page will not form properly.  This problem does not occur if distinct ports are used for each HTTP server, as everything remains at the root path.

Both approaches are described below: use the one that fits.

All of the actions below are carried out on the machine that is on the public internet.

In both cases, when done, restart `nginx` with `sudo systemctl restart nginx`, open a browser and make an HTTPS connection to the path you have told `nginx` to listen for and you should end up at the HTTP server at the other end of the given tunnel.  If you get "page not found", use `netstat -tulpn` to check that the port is listed as a TCP listening port on the machine that is on the public internet.  If it is not check the status of the tunnel on the client machine with something like `sudo systemctl status tunnel-http`.

## By Path
Assuming that the end of a tunnel is on port 8888 and you want to end up at the root of that HTTP page heirarchy:

- Edit the file `/etc/nginx/sites-available/remote_machine/remote_machine_port_default` to add a new `location`, something like:

  ```
          location /some/path/ {
                  proxy_pass http://localhost:8888/;
          }
  ```

## By Port
The exposed port will need to be different to the end-of-tunnel port (since both ports hang off the same network adapter): you will need to decide on your strategy for this (e.g. separate them by some fixed number or start the exposed ports at a different number).  Assuming that the end of a tunnel is on port 8888 and you expose it as port 5000:

- Create a new file, `/etc/nginx/sites-available/remote_machine/remote_machine_port_5000` with contents something like:

  ```
  server {
          listen      5000 ssl;
          listen [::]:5000 ssl;

          include /etc/nginx/sites-available/remote_machine/common.cfg;

          location / {
                  proxy_pass http://localhost:8888/;
          }
  }
  ```

- Enable this server block with:

  ```
  sudo ln -s /etc/nginx/sites-available/remote_machine/remote_machine_port_5000 /etc/nginx/sites-enabled/
  ```

- Open port 5000 on the network firewall (and `ufw` if active).

- Note: if you end up doing everything this way you may be able to close ports 80 and 443 on the network firewall of the machine on the public internet once more (unless, of course, you need the ports to be open for Cerbot certificate renewal).

## Other Hints
- For an HTTP server that relies on websockets, you may need to add the following to the `location` area of that `nginx` site configuration file:

  ```
                  # WebSocket support
                  proxy_http_version 1.1;
                  proxy_set_header Upgrade $http_upgrade;
                  proxy_set_header Connection "upgrade";
  ```

# Requesting Access
The instructions that might be provided to someone who would like to access `https://remote_machine` are as follows.

## Arranging Access For A Linux Machine
Please generate a key and a certificate signing request using OpenSSL with:

  ```
  openssl genrsa -des3 -out remote_machine.key 4096
  openssl req -new -key remote_machine.key -out remote_machine.devicename.csr
  ```

...where the key file should be password protected and `devicename` is replaced with something that uniquely identifies that particular device (e.g. in my case it would be `RobLaptop`), entering that same string in the `Organisation Name` field of the CSR and also populating the `E-mail Address` field of the CSR with your e-mail address; everything else in there can be left blank by just pressing `.` and then `<enter>`.

Keep the `.key` file safely somewhere (do not reveal it to anyone) and send the file `remote_machine.devicename.csr` to [name@address](mailto:name@address).

You will get back a signed certificate, valid for 365 days, plus the CA certificate for the `remote_machine`, along with instructions on how to load those into Firefox.

## Arranging Access For A Windows Machine
If you can, [install OpenSSL](https://wiki.openssl.org/index.php/Binaries) and do the same as above, noting that, if you happen to have `Git` installed, you can find OpenSSL in `C:\Program Files\Git\usr\bin\`.  If you do not have OpenSSL, just e-mail the `devicename` of the machine to [name@address](mailto:name@address).  You will get back a `.pfx` file that you can install in Windows, allowing you to use any Windows browser.

## Arranging Access For An Android Phone
E-mail a `devicename` for your phone to [name@address](mailto:name@address).  You will get back a `.pfx` file that you can install in the phone, allowing you to use any browser.