#!/usr/bin/env bash

PASSWORD=changeit
KEYSTORE=keystore.jks
TRUSTSTORE=truststore.jks
CAALIAS=ca
CLIENTNAME=joe.bloggs@acme.com
CLIENTALIAS=joe

# Generate a certificate authority (CA)
keytool -genkey -alias $CAALIAS -ext BC=ca:true \
	-keyalg RSA -keysize 4096 -sigalg SHA512withRSA -keypass $PASSWORD \
	-validity 3650 \
	-keystore $KEYSTORE -storepass $PASSWORD \
	-dname "CN=ACME CORP, OU=ACME SECURITY, O=ACME CORP, L=ACME CITY, ST=ACME PROVINCE, C=AC"

# Export certificate authority
keytool -export -alias $CAALIAS -file "$CAALIAS.crt" -rfc \
	-keystore $KEYSTORE -storepass $PASSWORD

# Import certificate authority into a new truststore
keytool -import -trustcacerts -noprompt -alias "CAALIAS" -file "$CAALIAS.crt" \
	-keystore $TRUSTSTORE -storepass $PASSWORD

# Generate client certificate
keytool -genkey -alias $CLIENTALIAS \
	-keyalg RSA -keysize 4096 -sigalg SHA512withRSA -keypass $PASSWORD \
	-validity 3650 \
	-keystore $TRUSTSTORE -storepass $PASSWORD \
	-dname "CN=$CLIENTNAME, OU=ACME SECURITY, O=ACME CORP, L=ACME CITY, ST=ACME PROVINCE, C=AC"

# Generate a host certificate signing request
keytool -certreq -alias $CLIENTALIAS -ext BC=ca:true \
	-keyalg RSA -keysize 4096 -sigalg SHA512withRSA \
	-validity 3650 -file "$CLIENTALIAS.csr" \
	-keystore $TRUSTSTORE -storepass $PASSWORD

# Generate signed certificate with the certificate authority
keytool -gencert -alias $CAALIAS \
	-validity 3650 -sigalg SHA512withRSA \
	-infile "$CLIENTALIAS.csr" -outfile "$CLIENTALIAS.crt" -rfc \
	-keystore $KEYSTORE -storepass $PASSWORD

# Import signed certificate into the truststore
keytool -import -trustcacerts -alias $CLIENTALIAS \
	-file "$CLIENTALIAS.crt" \
	-keystore $TRUSTSTORE -storepass $PASSWORD

# Export private certificate for importing into a browser
keytool -importkeystore -srcalias $CLIENTALIAS \
	-srckeystore $TRUSTSTORE -srcstorepass $PASSWORD \
	-destkeystore "$CLIENTALIAS.p12" -deststorepass $PASSWORD \
	-deststoretype PKCS12 
