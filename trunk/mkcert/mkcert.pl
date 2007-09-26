#!/usr/bin/perl
#
# $Id: mkcert.pl,v 1.8 2007-09-26 22:54:43 atterdag Exp $
#
# AUTHOR: Valdemar Lemche <valdemar@lemche.net>
#
# VERSION: 0.3.1d
#
# PURPOSE: Generates scripts to easily create and manage certificates and keys.
#
# Get the latest version from http://valdemar.lemche.net
#
# COPYRIGHT: See the copyright file distributed with this script.
#

# Strict memory usage is always a good thing
use strict;

# Allows options sent to script
use Getopt::Long;

# Sets the global global configuration hash
our (%configuration);

# Get the options from the command line
GetOptions(
			'nsCertType=s'     => \@{ $configuration{'nsCertType'} },
			'subjectAltName=s' => \@{ $configuration{'subjectAltNames'} },
			'commonName=s'     => \$configuration{'commonName'},
			'conf=s'           => \$configuration{'file'}
);

# Valid options supplied with script
&validate_options();

# Read parameters from the configuration file
&read_configuration_file( $configuration{'file'} );

# Do some sanity checks
&sanity_checks();

# Make the openssl.cnf configuration for commonName
&make_openssl_cnf();

# Generate the script which can generate the certificate
&make_creation_script();

# Generate the script which can generate the certificate
&make_signing_script();

# Generate the script which can revokes the certificate
&make_revokation_script();

# Generate the script which can renews the certificate
&make_renewal_script();

# Print a summary
&summary();

# Run scripts?
&run_scripts();

sub validate_options {

	print "Validating options ...\n";

	my $syntax =
"Usage: mkcert -commonName <commonName> [-nsCertType <server> [-nsCertType = <type>]] [-subjectAltName <subjectAltName> [-subjectAltName <subjectAltName>]] [-conf <configuration-file>]\n";

	# If commonName have not been defined then die
	die $syntax . "\n\tcommonName have not been set -- exitting!\n\n"
	  if !( $configuration{'commonName'} );

	# If nsCertType have been defined but doesn't have the right syntax then die
	foreach my $nsCertType ( @{ $configuration{'nsCertType'} } ) {
		unless (    ( $nsCertType eq 'server' )
				 || ( $nsCertType eq 'client' )
				 || ( $nsCertType eq 'email' )
				 || ( $nsCertType eq 'objsign' ) )
		{
			die $syntax . "

                nsCertType can be the following:

                        server:  A typical server certificate
                        client:  A typical client certificate
                        email:   Allowed to sign an email
                        objsign: Allowed to sign other objects

";
		}
	}

# If subjectAltName have been defined but doesn't have the right syntax then die
	foreach my $subjectAltName ( @{ $configuration{'subjectAltNames'} } ) {
		unless (    ( $subjectAltName =~ /^email:/ )
				 || ( $subjectAltName =~ /^URI:/ )
				 || ( $subjectAltName =~ /^DNS:/ )
				 || ( $subjectAltName =~ /^RID:/ )
				 || ( $subjectAltName =~ /^IP:/ )
				 || ( $subjectAltName =~ /^dirName:/ )
				 || ( $subjectAltName =~ /^otherName:/ ) )
		{
			die $syntax . "

                subjectAltName can be the following:

                        email:     <an email address>
                        URI:       <a uniform resource indicator>
                        DNS:       <a DNS domain name>
                        RID:       <a registered ID: OBJECT IDENTIFIER>
                        IP:        <an IP address>
                        dirName:   <a distinguished name>
                        otherName: <otherName can include arbitrary data associated
                                   with an OID: the value should be the OID followed
                                   by a semicolon and the content in standard
                                   ASN1_generate_nconf() format.

";
		}
	}

	# If a configuration file was not defined as a option
	unless ( $configuration{'file'} ) {

		# Then set a default one
		$configuration{'file'} = "./mkcert.cfg";
	}

}

sub read_configuration_file {
	print "Reading configuration file ...\n";

	# Defines the required parameters in the configuration file
	@{ $configuration{'parameters'}->{'required'} } = qw(
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
	@{ $configuration{'parameters'}->{'optional'} } = qw(
	  cacert
	  cakey
	  issuerAltName
	  crlDistributionPoints
	);

	# Defines the optional netscape parameters in the configuration file
	@{ $configuration{'parameters'}->{'netscape'} } = qw(
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
		if (    $line =~ /^#/
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

		# Strips any trailing spaces for parameter
		$parameter =~ s/\s+$//g;

		# Strips any leading spaces for value
		$value =~ s/^\s+//g;

		# Strips any trailing spaces for value
		$value =~ s/\s+$//g;

		# Defines a validation check
		our $validated = 0;

		# iterate over parameter groups
		foreach my $valid_parameters_group (
									 keys( %{ $configuration{'parameters'} } ) )
		{

			# For each valid parameter
			foreach my $valid_parameter (
				  @{ $configuration{'parameters'}->{$valid_parameters_group} } )
			{

				# if the valid parameter matches the parameter
				if ( $valid_parameter eq $parameter ) {

					# then use the value from the configuration file
					$configuration{$valid_parameter} = $value;

					# declare the parameter as validated
					$validated = 1;

					# and break the loop
					last;
				}
			}

			# if validated
			if ( $validated eq "1" ) {

				# then break loop
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
	  my $required_parameter ( @{ $configuration{'parameters'}->{'required'} } )
	{

		# if parameter is unset
		if ( $configuration{$required_parameter} eq "" ) {

			# then die
			die $required_parameter . " haven't been defined -- exitting!\n";
		}
	}
}

sub sanity_checks {

	print "Checks if files and directories exist ...\n";

	# if directory where cnf files are placed doens't exist, then create it'
	&check_directory( $configuration{'ssldir'} . "/configs" );

# if directory where generation scripts are placed doens't exist, then create it'
	&check_directory( $configuration{'ssldir'} . "/scripts" );

	# If the CA certificate was defined in the configuration file
	&check_ca( "cacert", "cacert.pem", "CA certificate" );

	# If the CA key was defined in the configuration file
	&check_ca( "cakey", "private/cakey.pem", "CA key" );
}

sub check_directory {

	# unless defined directory exist
	unless ( -d $_[0] ) {

		# then create
		mkdir("$_[0]")
		  || die "FAILED\ncannot create, " . $_[0] . ": " . $! . "\n";
	}
}

sub check_ca {

	# If the $_[0] was defined in the configuration file
	if ( $configuration{ $_[0] } ) {

		# then if file doesn't 'exist
		unless ( -f $configuration{ $_[0] } ) {

			# then print
			die "FAILED\nthe "
			  . $_[2]
			  . " defined in "
			  . $configuration{'file'} . ", "
			  . $configuration{ $_[0] }
			  . "doesn't exist -- exitting\n";
		}
	} else {

		# otherwise check if it exist at the default location
		if ( -f $configuration{'ssldir'} . "/" . $_[1] ) {

			# then use the default location
			$configuration{ $_[0] } = $configuration{'ssldir'} . "/" . $_[1];
		} else {

			# or die, saying that it can't find it
			die "FAILED\ncan't find your "
			  . $_[2]
			  . " , try defining it in the configurtion file, "
			  . $configuration{'file'}
			  . " -- exitting\n";
		}
	}
}

sub make_openssl_cnf {

	print "Generating OpenSSL configuration ...\n";

	# Open the .cnf file
	open( CNF,
		 " >$configuration{'ssldir'}/configs/$configuration{'commonName'}.cnf" )
	  || die "FAILED\ncannot open file, "
	  . $configuration{'ssldir'}
	  . "/configs/"
	  . $configuration{'commonName'}
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
default_keyfile         = \$dir/private/$configuration{'commonName'}-key.pem
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
commonName_default              = $configuration{'commonName'}
commonName_max                  = 64
emailAddress                    = Email Address
emailAddress_default            = root\@$configuration{'commonName'}
emailAddress_max                = 64
[ req_attributes ]
challengePassword               = A challenge password
challengePassword_min           = 4
challengePassword_max           = 20
unstructuredName                = An optional company name
[ usr_cert ]
basicConstraints=CA:FALSE
EOT

	# define the nsCertType if requested
	unless ( $configuration{'nsCertType'} eq "" ) {
		print CNF 'nsCertType                      = ';
		our ($nsCertType_left);
		until ( $nsCertType_left eq 0 ) {
			my $nsCertType = shift( @{ $configuration{'nsCertType'} } );
			print CNF $nsCertType;
			$nsCertType_left = @{ $configuration{'nsCertType'} };
			unless ( $nsCertType_left eq 0 ) {
				print CNF ", ";
			}
		}
		print CNF "\n";
	}

	# Print a little more standard stuff
	print CNF <<EOT;
nsComment                       = "mkcert.pl generated certificate"
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid,issuer
EOT
	for
	  my $netscape_parameter ( @{ $configuration{'parameters'}->{'netscape'} } )
	{
		unless ( $configuration{$netscape_parameter} eq "" ) {
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

	# If there were any subjectAltNames supplied
	if ( $configuration{'subjectAltNames'}->[0] ) {

		# then add the parameter
		print CNF "subjectAltName = ";

		# first count how many subjectAltNames are supplied
		my $subjectAltName_totals = @{ $configuration{'subjectAltNames'} };

		# sets a counter
		our $subjectAltName_count = 0;

		# until counter equals the amount of subjectAltNames
		until ( $subjectAltName_count eq $subjectAltName_totals ) {

			# add each subjectAltName to the parameter
			print CNF $configuration{'subjectAltNames'}
			  ->[$subjectAltName_count];

			# increase the counter
			$subjectAltName_count++;

			# unless there are no more subjectAltNames to be added
			unless (
				   $configuration{'subjectAltNames'}->[$subjectAltName_count] eq
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
	  . $configuration{'commonName'}
	  . ".cnf: "
	  . $! . "\n";
}

sub make_creation_script {
	print "Generating key and certificate request creation script ... \n";

	# Get localtime
	my $date = localtime();

	# Open the certificate generation script
	open( SCRIPT,
">$configuration{'ssldir'}/scripts/create-$configuration{'commonName'}.sh"
	  )
	  || die "FAILED\ncannot open file, "
	  . $configuration{'ssldir'}
	  . "/scripts/create-"
	  . $configuration{'commonName'} . ".sh"
	  . $! . "\n";
	print SCRIPT <<EOF;
#!/bin/sh
#
# This script generates the CSR and KEY for the CommonName:
#
#       $configuration{'commonName'}
#
# This script was generated by mkcert.pl at $date
#

echo "Running $configuration{'ssldir'}/scripts/create-$configuration{'commonName'}.sh"
echo

echo "Recording the PWD you're at"
pushd . > /dev/null
echo

echo "Going to your OpenSSL directory"
cd "$configuration{'ssldir'}"
echo

echo "Recording your old umask"
UMASK=`umask`
echo

echo "Setting a new strict umask"
umask 0127
echo

echo "Generate certificate req and certificate private key"
openssl req -outform PEM -out "$configuration{'ssldir'}/$configuration{'commonName'}-req.pem" -newkey rsa:1024 -nodes -config "$configuration{'ssldir'}/configs/$configuration{'commonName'}.cnf" -batch
echo

echo "Loosens the permissions on CSR"
chmod 0644 "$configuration{'ssldir'}/$configuration{'commonName'}-req.pem"
echo

echo "Changes the group ownership of the private key"
chgrp ssl "$configuration{'ssldir'}/private/$configuration{'commonName'}-key.pem"
echo

echo "Restores the old umask"
umask \${UMASK}
echo

echo "Return to old PWD"
popd > /dev/null
echo

echo "Running the signing script"
. "$configuration{'ssldir'}/scripts/sign-$configuration{'commonName'}.sh"
echo
EOF
	close(SCRIPT)
	  || die "FAILED\ncannot close file, "
	  . $configuration{'ssldir'}
	  . "/scripts/create-"
	  . $configuration{'commonName'} . ".sh"
	  . $! . "\n";
	chmod( 0755,
"$configuration{'ssldir'}/scripts/create-$configuration{'commonName'}.sh"
	);

}

sub make_signing_script {
	print "Generating certificate request signing script ... \n";

	# Get localtime
	my $date = localtime();

	# Open the signing script
	open( SCRIPT,
		">$configuration{'ssldir'}/scripts/sign-$configuration{'commonName'}.sh"
	  )
	  || die "FAILED\ncannot open file, "
	  . $configuration{'ssldir'}
	  . "/scripts/sign-"
	  . $configuration{'commonName'} . ".sh"
	  . $! . "\n";
	print SCRIPT <<EOF;
#!/bin/sh
#
# This script sign the CSR for the CommonName:
#
#       $configuration{'commonName'}
#
# With the CA key:
#
#       $configuration{'cakey'}
#
# Which creates the certificate:
#
#       $configuration{'ssldir'}/$configuration{'commonName'}-cert.pem
#
# This script was generated by mkcert.pl at $date
#

echo "Running $configuration{'ssldir'}/scripts/sign-$configuration{'commonName'}.sh"
echo

echo "Recording the PWD you're at"
pushd . > /dev/null
echo

echo "Going to your OpenSSL directory"
cd "$configuration{'ssldir'}"
echo

echo "Recording your old umask"
UMASK=`umask`
echo

echo "Sets a looser umask"
umask 0122
echo

echo "Generate the certificate and signs it with the ca-key"
openssl ca -config "$configuration{'ssldir'}/configs/$configuration{'commonName'}.cnf" -out "$configuration{'ssldir'}/$configuration{'commonName'}-cert.pem" -policy policy_anything -batch -infiles "$configuration{'ssldir'}/$configuration{'commonName'}-req.pem"
echo

echo "Create DER formatted certificate from the PEM formatted certificate"
openssl x509 -in "$configuration{'ssldir'}/$configuration{'commonName'}-cert.pem" -out "$configuration{'ssldir'}/$configuration{'commonName'}-cert.der" -outform DER
echo

echo "Setting a more scrict umask"
umask 0120
echo

echo "Creating PKCS12 formatted certificate from the PEM formatted certificate and PEM formmated key"
openssl pkcs12 -export -in "$configuration{'ssldir'}/$configuration{'commonName'}-cert.pem" -inkey "$configuration{'ssldir'}/private/$configuration{'commonName'}-key.pem" -out "$configuration{'ssldir'}/$configuration{'commonName'}-cert.p12" -name "$configuration{'commonName'}"
echo

echo "Restores the old umask"
umask \${UMASK}
echo

echo "Return to old PWD"
popd > /dev/null
echo
EOF
	close(SCRIPT)
	  || die "FAILED\ncannot close file, "
	  . $configuration{'ssldir'}
	  . "/scripts/sign-"
	  . $configuration{'commonName'} . ".sh"
	  . $! . "\n";
	chmod( 0755,
"$configuration{'ssldir'}/scripts/sign-$configuration{'commonName'}.sh"
	);

}

sub make_revokation_script {
	print "Generating revokation script ... \n";

	# Get localtime
	my $date = localtime();

	# Open the certificate revokation script
	open( SCRIPT,
">$configuration{'ssldir'}/scripts/revoke-$configuration{'commonName'}.sh"
	  )
	  || die "FAILED\ncannot open file, "
	  . $configuration{'ssldir'}
	  . "/scripts/revoke-"
	  . $configuration{'commonName'} . ".sh"
	  . $! . "\n";
	print SCRIPT <<EOF;
#!/bin/sh
#
# This script revokes the certificate with the CommonName:
#
#       $configuration{'commonName'}
#
# This script was generated by mkcert.pl at $date
#

echo "Running $configuration{'ssldir'}/scripts/revoke-$configuration{'commonName'}.sh"
echo

echo "Recording the PWD you're at"
pushd . > /dev/null
echo

echo "Going to your OpenSSL directory"
cd "$configuration{'ssldir'}"
echo

echo "Revokes the script at update key database"
openssl ca -config "$configuration{'ssldir'}/configs/$configuration{'commonName'}.cnf" -revoke "$configuration{'ssldir'}/$configuration{'commonName'}-cert.pem"
echo

echo "Generate/updates certificate revokation list"
openssl ca -config "$configuration{'ssldir'}/configs/$configuration{'commonName'}.cnf" -gencrl -out "$configuration{'ssldir'}/crl/ca.crl"
echo

echo "Returning to old PWD"
popd > /dev/null
echo

EOF
	close(SCRIPT)
	  || die "FAILED\ncannot close file, "
	  . $configuration{'ssldir'}
	  . "/scripts/revoke-"
	  . $configuration{'commonName'} . ".sh"
	  . $! . "\n";
	chmod( 0755,
"$configuration{'ssldir'}/scripts/revoke-$configuration{'commonName'}.sh"
	);

}

sub make_renewal_script {
	print "Generating renewal script ... \n";

	# Get localtime
	my $date = localtime();

	# Open the certificate renewal script
	open( SCRIPT,
">$configuration{'ssldir'}/scripts/renew-$configuration{'commonName'}.sh"
	  )
	  || die "FAILED\ncannot open file, "
	  . $configuration{'ssldir'}
	  . "/scripts/renew-"
	  . $configuration{'commonName'} . ".sh"
	  . $! . "\n";
	print SCRIPT <<EOF;
#!/bin/sh
#
# This script renews the certificate with the CommonName:
#
#       $configuration{'commonName'}
#
# This script was generated by mkcert.pl at $date
#

echo "Running $configuration{'ssldir'}/scripts/renew-$configuration{'commonName'}.sh"
echo

echo "Record the PWD you're at"
pushd . > /dev/null
echo

echo "Going to your OpenSSL directory"
cd "$configuration{'ssldir'}"
echo

echo "Calls the revokation script to revoke old certificate"
. "$configuration{'ssldir'}/scripts/revoke-$configuration{'commonName'}.sh"
echo

echo "Calls the signing script to generate a new signed certificate from the CSR"
. "$configuration{'ssldir'}/scripts/sign-$configuration{'commonName'}.sh"
echo

echo "Return to old PWD"
popd > /dev/null
echo

EOF
	close(SCRIPT)
	  || die "FAILED\ncannot close file, "
	  . $configuration{'ssldir'}
	  . "/scripts/renew-"
	  . $configuration{'commonName'} . ".sh"
	  . $! . "\n";
	chmod( 0755,
"$configuration{'ssldir'}/scripts/renew-$configuration{'commonName'}.sh"
	);

}

sub summary {

	# this subrouting just prints a summary with the .cnf file and script
	print "\n\nSUMMARY:\n\n";
	print "OpenSSL configuration for this server certificate is saved as:\n";
	print "\t"
	  . $configuration{'ssldir'}
	  . "/configs/"
	  . $configuration{'commonName'}
	  . ".cnf\n\n";
	print "Script to generate certificate request and key is saved as:\n";
	print "\t"
	  . $configuration{'ssldir'}
	  . "/scripts/create-"
	  . $configuration{'commonName'}
	  . ".sh\n\n";
	print
"Script to sign certificate request and generate signed certificate is saved as:\n";
	print "\t"
	  . $configuration{'ssldir'}
	  . "/scripts/sign-"
	  . $configuration{'commonName'}
	  . ".sh\n\n";
	print "Script to renew a certificate is saved as:\n";
	print "\t"
	  . $configuration{'ssldir'}
	  . "/scripts/renew-"
	  . $configuration{'commonName'}
	  . ".sh\n\n";
	print "Script to revoke a certificate is saved as:\n";
	print "\t"
	  . $configuration{'ssldir'}
	  . "/scripts/revoke-"
	  . $configuration{'commonName'}
	  . ".sh\n\n";
}

sub run_scripts {

	# Should we just run the generation script now?
	print "Run creation script now? (this will also sign the CSR) [yes]: ";

	# Read input from STDIN
	my $answer = <STDIN>;

	# Strip line-ending
	chomp($answer);

	# If input equals something with yes or just [ENTER]
	if ( $answer eq "yes" || $answer eq "y" || $answer eq "Y" || $answer eq "" )
	{

		# then run the script
		system(   "\"$configuration{'ssldir'}/scripts/create-$configuration{'commonName'}.sh\""
		);
	}
}
