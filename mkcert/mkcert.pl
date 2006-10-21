#!/usr/bin/perl
#
# $Id: mkcert.pl,v 1.1 2006-10-21 09:10:55 atterdag Exp $
#
# AUTHOR: Valdemar Lemche <valdemar@lemche.net>
#
# VERSION: 0.1b stable
#
# PURPOSE: Easily generate server certificate and key.
#
# USAGE:
# Set up a CA certificate (with key). If you don't know how to, then please
# refer to http://valdemar.lemche.net/documents/openssl/certificates on how to.
#
# Edit ./mkcert.cfg (the parameters is described in the file), and run the
# command:
#
#       # ./mkcert.pl -fqdn <fqdn> [-cname cname1 [-cname cname2]]
#
# This will create in a certificate plus key.
#
# CHANGELOG:
# mkcert.pl (0.1b) stable; urgency=low
#
#   * Initial release
#
#  -- Valdemar Lemche <valdemar@lemche.net>  Mon, 21 Oct 2006 10:50 +0100
#
# Get the latest version from http://valdemar.lemche.net
#
# mkcert.pl is Copyright (C) 2006 Valdemar Lemche.  All rights reserved.
# This script is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.
#
# This script is released TOTALLY AS-IS. If it will have any negative impact
# on your systems, make you sleepless at night or even cause of World War III;
# I will claim no responsibility! You may use this script at you OWN risk.
#

# Strict memory usage is always a good thing
use strict;

# Allows options sent to script
use Getopt::Long;

# Sets the global global configuration hash
our (%configuration);

# Get the options from the command line
GetOptions(
	    'cname=s' => \@{ $configuration{'cnames'} },
	    'fqdn=s'  => \$configuration{'fqdn'},
	    'conf=s'  => \$configuration{'file'}
);

# If FQDN have not been defined then die
die
"Usage: mkcert -fqdn <FQDN> [-cname CNAME[,CNAME]] [-conf configuration-file]\n\n\tFQDN have not been set -- exitting!\n\n"
  if !( $configuration{'fqdn'} );

# If a configuration file was not defined as a option
unless ( $configuration{'file'} ) {

	# Then set a default one
	$configuration{'file'} = "./mkcert.cfg";
}

# Read parameters from the configuration file
&read_configuration_file( $configuration{'file'} );

# Do some sanity checks
&checks();

# Make the openssl.cnf configuration for FQDN
&make_cnf();

# Generate the script which can generate the certificate
&generate_script();

# Print a summary
&summary();

# Should we just run the generation script now?
print "Run script now? [yes]: ";

# Read input from STDIN
my $answer = <STDIN>;

# Strip line-ending
chomp($answer);

# If input equals something with yes or just [ENTER]
if ( $answer eq "yes" || $answer eq "y" || $answer eq "Y" || $answer eq "" ) {

	# then run the script
	system("$configuration{'ssldir'}/scripts/$configuration{'fqdn'}.sh");
}

sub read_configuration_file {
	print "Reading configuration file: ";

	# Defines the required parameters in the configuration file
	@{ $configuration{'required_parameters'} } = qw(
	  days
	  country
	  locality
	  nsCaRevocationUrl
	  organization
	  organizationalUnit
	  ssldir
	  stateOrProvince
	);

	# Defines the optional parameters in the configuration file
	@{ $configuration{'optional_parameters'} } = qw(
	  cacert
	  cakey
	  issuerAltName
	  crlDistributionPoints
	);

	# Defines the optional netscape parameters in the configuration file
	@{ $configuration{'netscape_parameters'} } = qw(
	  nsBaseUrl
	  nsCaRevocationUrl
	  nsRevocationUrl
	  nsRenewalUrl
	  nsCaPolicyUrl
	);

	# Opens configuration file
	open( CONFIG_FILE, $_[0] )
	  || die "cannot open " . $_[0] . ": " . $! . "\n";

	# Parses the configuration file, line for line
	foreach my $line (<CONFIG_FILE>) {

		# Remove line ending
		chomp($line);

		# If the line is a comment,
		# contains only spaces
		# or tabs,
		# or is a an empty line
		if (     $line =~ /^#/
		      || $line =~ /^\s+$/
		      || $line =~ /^\s+$/
		      || $line =~ /^\t+$/
		      || $line =~ /^$/ )
		{

			# then goto to next line
			next;
		}

		# Splits the line into parameter and value
		my ( $parameter, $value ) = split( / = /, $line );

		# Strips any trailing spaces
		$parameter =~ s/\s+$//g;

		# Strips any leading spaces
		$value =~ s/^\s+//g;

		# Defines a validation check
		our $validated = 0;

		# Concanate required and optional parameters
		my @valid_parameters = (
				    @{ $configuration{'required_parameters'} },
				    @{ $configuration{'optional_parameters'} },
				    @{ $configuration{'netscape_parameters'} }
		);

		# For each valid parameter
		foreach my $valid_parameter (@valid_parameters) {

			# if the valid parameter matches the parameter
			if ( $valid_parameter eq $parameter ) {

			       # then use the value from the configuration file
				$configuration{$valid_parameter} = $value;

				# declare the parameter as validated
				$validated = 1;

				# and go to next line
				last;
			}
		}

		# If the parameter is not a valid setting
		unless ( $validated eq "1" ) {

			# then die
			die 'The parameter, "'
			  . $parameter . '"'
			  . " used in "
			  . $_[0]
			  . " is unknown -- exitting!\n";
		}

	}

	# Close configuration file
	close(CONFIG_FILE);

	# For each required parameter
	foreach
	  my $required_parameter ( @{ $configuration{'required_parameters'} } )
	{

		# if parameter is unset
		if ( $configuration{$required_parameter} eq "" ) {

			# then die
			die $required_parameter
			  . " haven't been defined -- exitting!\n";
		}
	}
	print "done\n";
}

sub checks {

	print "Checks if files and directories exist: ";

       # if directory where cnf files are placed doens't exist, then create it'
	unless ( -d $configuration{'ssldir'} . "/configs" ) {
		mkdir("$configuration{'ssldir'}/configs")
		  || die "FAILED\ncannot create, "
		  . $configuration{'ssldir'}
		  . "/configs: "
		  . $! . "\n";
	}

# if directory where generation scripts are placed doens't exist, then create it'
	unless ( -d $configuration{'ssldir'} . "/scripts" ) {
		mkdir("$configuration{'ssldir'}/scripts")
		  || die "FAILED\ncannot create, "
		  . $configuration{'ssldir'}
		  . "/scripts: "
		  . $! . "\n";
	}

	# If the CA certificate was defined in the configuration file
	if ( $configuration{'cacert'} ) {

		# then if file doesn't 'exist
		unless ( -f $configuration{'cacert'} ) {

			# then die
			die "FAILED\nthe CA Certificate defined in "
			  . $configuration{'file'} . ", "
			  . $configuration{'cacert'}
			  . "doesn't exist -- exitting\n";
		}
	} else {

		# otherwise check if it exist at the default location
		if ( -f "$configuration{'ssldir'}/cacert.pem" ) {

			# then use the default location
			$configuration{'cacert'} = "\$dir/cacert.pem";
		} else {

			# or die, saying that it can't find it
			die
"FAILED\ncan't find your CA Certificate, try defining it in the configurtion file, "
			  . $configuration{'file'}
			  . " -- exitting\n";
		}
	}

	# If the CA key was defined in the configuration file
	if ( $configuration{'cakey'} ) {

		# if file doesn't exist
		unless ( -f $configuration{'cakey'} ) {

			# then die
			die "FAILED\nthe CA Key defined in "
			  . $configuration{'file'} . ", "
			  . $configuration{'cakey'}
			  . "doesn't exist -- exitting\n";
		}
	} else {

		# or check if it exist at the default location
		if ( -f "$configuration{'ssldir'}/private/cakey.pem" ) {

			# then use the default location
			$configuration{'cakey'} = "\$dir/private/cakey.pem";
		} else {

			# or die, saying that it can't find it
			die
"FAILED\ncan't find your CA Certificate, try defining it in the configurtion file, "
			  . $configuration{'file'}
			  . " -- exitting \n ";
		}
	}
	print "done\n";
}

sub make_cnf {

	print "Generating OpenSSL configuration: ";

	# Open the .cnf file
	open( CNF,
	       " >$configuration{'ssldir'}/configs/$configuration{'fqdn'}.cnf"
	  )
	  || die "FAILED\ncannot open file, "
	  . $configuration{'ssldir'}
	  . "/configs/"
	  . $configuration{'fqdn'}
	  . ".cnf: "
	  . $! . "\n";

	# Generate the standard configuration using the values from mkcert.cfg
	# and the options
	print CNF <<EOT;
HOME                    = .
RANDFILE                = \$ENV::HOME/.rnd
oid_section             = new_oids
[ new_oids ]
[ ca ]
default_ca      = CA_default
[ CA_default ]
dir             = $configuration{'ssldir'}
certs           = \$dir/certs
crl_dir         = \$dir/crl
database        = \$dir/index.txt
new_certs_dir   = \$dir/newcerts
certificate     = $configuration{'cacert'}
serial          = \$dir/serial
crlnumber       = \$dir/crlnumber
crl             = \$dir/crl.pem
private_key     = $configuration{'cakey'}
RANDFILE        = \$dir/private/.rand
x509_extensions = usr_cert
name_opt        = ca_default
cert_opt        = ca_default
default_days    = $configuration{'days'}
default_crl_days= 30
default_md      = sha1
preserve        = no
policy          = policy_match
[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
[ req ]
dir                     = $configuration{'ssldir'}
default_bits            = 1024
default_keyfile         = \$dir/private/$configuration{'fqdn'}-key.pem
distinguished_name      = req_distinguished_name
attributes              = req_attributes
x509_extensions = v3_ca # The extentions to add to the self signed cert
string_mask = nombstr
[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = $configuration{'country'}
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = $configuration{'stateOrProvince'}
localityName                    = Locality Name (eg, city)
localityName_default            = $configuration{'locality'}
0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = $configuration{'organization'}
organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default  = $configuration{'organizationalUnit'}
commonName                      = Common Name (eg, YOUR name)
commonName_default              = $configuration{'fqdn'}
commonName_max                  = 64
emailAddress                    = Email Address
emailAddress_default            = root\@$configuration{'fqdn'}
emailAddress_max                = 64
[ req_attributes ]
challengePassword               = A challenge password
challengePassword_min           = 4
challengePassword_max           = 20
unstructuredName                = An optional company name
[ usr_cert ]
basicConstraints=CA:FALSE
nsComment                       = "mkcert.pl generated certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOT
	for
	  my $netscape_parameter ( @{ $configuration{'netscape_parameters'} } )
	{
		if ( $configuration{$netscape_parameter} ) {
			print CNF $netscape_parameter . " = "
			  . $configuration{$netscape_parameter} . "\n";
		}
	}
	if ( $configuration{'issuerAltName'} ) {
		print CNF "issuerAltName = URI:"
		  . $configuration{'issuerAltName'} . "\n";
	}
	if ( $configuration{'crlDistributionPoints'} ) {
		print CNF "crlDistributionPoints = URI:"
		  . $configuration{'crlDistributionPoints'} . "\n";
	}

	# If there were any CNAMES supplied
	if ( $configuration{'cnames'} ) {

		# then add the parameter
		print CNF "subjectAltName = ";

		# first count how many cnames are supplied
		my $cname_totals = @{ $configuration{'cnames'} };

		# sets a counter
		our $cname_count = 0;

		# until counter equals the amount of cnames
		until ( $cname_count eq $cname_totals ) {

			# add each cname to the parameter
			print CNF "DNS:"
			  . $configuration{'cnames'}->[$cname_count];

			# increase the counter
			$cname_count++;

			# unless there are no more cnames to be added
			unless ( $configuration{'cnames'}->[$cname_count] eq
				 "" )
			{

				# add a comma to seperate them
				print CNF ", ";
			}
		}

		# End the parameter
		print CNF "\n";
	}

	# Add the rest of the configuration
	print CNF <<EOT;
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true
[ crl_ext ]
authorityKeyIdentifier=keyid:always,issuer:always
[ proxy_cert_ext ]
basicConstraints=CA:FALSE
nsComment                       = "mkcert.pl generated certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo
EOT

	# close the .cnf file
	close(CNF)
	  || die "FAILED\ncannot close file, "
	  . $configuration{'ssldir'}
	  . "/configs/"
	  . $configuration{'fqdn'}
	  . ".cnf: "
	  . $! . "\n";

	print "done\n";
}

sub generate_script {
	print "Generating script: ";

	# Get localtime
	my $date = localtime();

	# Open the certificate generation script
	open( SCRIPT,
	       ">$configuration{'ssldir'}/scripts/$configuration{'fqdn'}.sh" )
	  || die "FAILED\ncannot open file, "
	  . $configuration{'ssldir'}
	  . "/scripts/"
	  . $configuration{'fqdn'} . ".sh"
	  . $! . "\n";
	print SCRIPT <<EOF;
#!/bin/sh
#
# This script generates the CSR, CRT and KEY for the CommonName:
#
#	$configuration{'fqdn'}
#
# And signs it with the CA key:
#
#	$configuration{'cakey'}
#
# This script was generated by mkcert.pl at $date
#

# Record the PWD you're at'
pushd .

# Go to you OpenSSL directory
cd $configuration{'ssldir'}

# Record your old umask
UMASK=`umask`

# Set a new strict umask
umask 0127

# Generate certificate req and certificate private key
openssl req -outform PEM -out $configuration{'ssldir'}/$configuration{'fqdn'}-req.pem -newkey rsa:1024 -nodes -config $configuration{'ssldir'}/configs/$configuration{'fqdn'}.cnf -batch

# Loosens the permissions on CSR
chmod 0644 $configuration{'ssldir'}/$configuration{'fqdn'}-req.pem

# Changes the group ownership of the private key
chgrp ssl $configuration{'ssldir'}/private/$configuration{'fqdn'}-key.pem

# Sets a looser umask
umask 0122

# Generate the certificate and signs it with the ca-key
openssl ca -out $configuration{'ssldir'}/$configuration{'fqdn'}-cert.pem -policy policy_anything -batch -infiles $configuration{'ssldir'}/$configuration{'fqdn'}-req.pem

# Restores the old umask
umask \${UMASK}

# Return to old PWD
popd
EOF
	close(SCRIPT)
	  || die "FAILED\ncannot close file, "
	  . $configuration{'ssldir'}
	  . "/scripts/"
	  . $configuration{'fqdn'} . ".sh"
	  . $! . "\n";
	chmod( 0755,
		"$configuration{'ssldir'}/scripts/$configuration{'fqdn'}.sh" );

	print "done\n";

}

sub summary {

	# this subrouting just prints a summary with the .cnf file and script
	print "\n\nSUMMARY:\n\n";
	print
	  "OpenSSL configuration for this server certificate is saved as:\n";
	print "\t"
	  . $configuration{'ssldir'}
	  . "/configs/"
	  . $configuration{'fqdn'}
	  . ".cnf\n\n";
	print "Script to generate certificate and key is saved as:\n";
	print "\t"
	  . $configuration{'ssldir'}
	  . "/scripts/"
	  . $configuration{'fqdn'}
	  . ".sh\n\n";
}
