#Instructions

## Create an API user
 
In your Oracle Cloud Infrastructure Console, under Identity > Users: 

* Click on "Create User"
* Set the Name to "CloudSploitAPI"
* Set the Description to "CloudSploit API Read Only Access"
* Click on "Create"

## Generate an API Signing Key

Please follow the instructions on: https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm

You will need:
* Private un-encrypted key: openssl genrsa -out ~/.oci/oci_api_key.pem 2048
* Public Key: openssl rsa -pubout -in ~/.oci/oci_api_key.pem -out ~/.oci/oci_api_key_public.pem
* Key Fingerprint: openssl rsa -pubout -outform DER -in ~/.oci/oci_api_key.pem | openssl md5 -c

## Save the Private un-encrypted key in this directory to run your scans