#Installation#

Just download the latest version from [my blog] (http://valdemar.lemche.net/2012/06/mkcertpl.html), and extract the tarball somewhere.<br>
##Usage##
Set up a CA certificate (with key). If you don’t know how to, then please refer to, [howto create you own CA and server certificate] (http://valdemar.lemche.net/2012/06/mini-howto-create-you-own-ca-and-server.html?page_id=16), on how to.<br>
Edit <code>./mkcert.cfg</code> (the parameters is described in the file), and run the command:<br>
<pre># ./mkcert.pl -commonName <commonName>
[-subjectAltName <subjectAltName>]
[-subjectAltName <subjectAltName>]</pre>
For example:<br>
<pre># ./mkcert.pl -commonName mailstore.se.lemche.net
-subjectAltName DNS:pop.se.lemche.net
-subjectAltName DNS:imap.se.lemche.net</pre>
This will create the configuration file:<br>
* **/etc/ssl/configs/mailstore.se.lemche.net.cnf**<br>
And the following scripts:<br>
* **/etc/ssl/scripts/create-mailstore.se.lemche.net.sh**<br>
* **/etc/ssl/scripts/sign-mailstore.se.lemche.net.sh**<br>
* **/etc/ssl/scripts/revoke-mailstore.se.lemche.net.sh**<br>
* **/etc/ssl/scripts/renew-mailstore.se.lemche.net.sh**<br>
The script create-mailstore.se.lemche.net.sh will create the ''Certificate Key'' and ''Certificate Signing Request (CSR)'' as:<br>  '''/etc/ssl/private/mailstore.se.lemche.net-key.pem'''<br> '''/etc/ssl/mailstore.se.lemche.net-req.pem'''<br>
The create script will also call the script sign-mailstore.se.lemche.net.sh.<br>
<blockquote>This will sign the CSR and create a PEM formattet certificate, convert<br>
the PEM certificate to a DER formattet certificate and finally create a<br>
PKCS#12 certificate from the certificate and the key. The files are:<br>  '''/etc/ssl/mailstore.se.lemche.net-cert.pem'''<br> '''/etc/ssl/mailstore.se.lemche.net-cert.der'''<br> '''/etc/ssl/mailstore.se.lemche.net-cert.p12'''<br>
Running revoke-mailstore.se.lemche.net.sh will revoke the certificate and update the ''Certificate Revokation List (CRL)'' of the CA.<br>
Running renew-mailstore.se.lemche.net.sh will first call revoke-mailstore.se.lemche.net.sh and then sign-mailstore.se.lemche.net.sh.<br>
That’s pretty easy, isn’t it?<br>
<h2>Copyright</h2>
'''mkcert.pl''' is Copyright (C) 2006, 2007 Valdemar Lemche.  All rights reserved.<br>
<br>
This script is free software; you can redistribute it and/or modify it under the same terms as Perl itself.<br>
This script is released TOTALLY AS-IS. If it will<br>
have any negative impact on your systems, make you sleepless at night or<br>
even cause World War III; I will claim no responsibility! You may use<br>
this script at you OWN risk.
