# CloudSploit For Oracle Cloud Infrastructure (OCI)

## Cloud Provider Configuration

1. Log into your Oracle Cloud console and navigate to Administration > Tenancy Details.
1. Copy your Tenancy OCID and paste it in the index file.
1. Navigate to Identity > Users.
1. Click on Create User.
1. Enter "CloudSploit", then enter "CloudSploit API Access" in the description.
1. Click on Create.
1. Copy the User OCID and paste it in the index file.
1. Follow the steps to Generate an API Signing Key listed on Oracle's Cloud Doc(https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#How).
1. Open the public key (oci_api_key_public.pem) in your preferred text editor and copy the plain text (everything). Click on Add Public Key, then click on Add.
1. Copy the public key fingerprint and paste it in the index file.
1. Open the private key (oci_api_key.pem) in your preferred text editor and paste it in the index file.
1. Navigate to Identity > Groups.
1. Click on Create Group.
1. Enter "SecurityAudit" in the Name field, then enter "CloudSploit Security Audit Access" in the description.
1. Click on Submit.
1. Click on the SecurityAudit group in the Groups List and Add the CloudSploit API User to the group.
1. Navigate to Identity > Policies.
1. Click on Create Policy.
1. Enter "SecurityAudit" in the Name field, then enter "CloudSploit Security Audit Policy" in the description.
1. Copy and paste the following statement:
1. ALLOW GROUP SecurityAudit to READ all-resources in tenancy
1. Click on Create.
1. Navigate to Identity > Compartments.
1. Select your root compartment or the compartment being audited.
1. Click on "Copy" by your Compartment OCID.

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

## Save
Save the private un-encrypted key in this directory to run your scans
