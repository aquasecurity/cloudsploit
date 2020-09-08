# CloudSploit For Google Cloud Platform (GCP)

## Cloud Provider Configuration

1. Log into your Google Cloud console and navigate to IAM Admin > Service Accounts.
1. Click on "Create Service Account".
1. Enter "CloudSploit" in the "Service account name", then enter "CloudSploit API Access" in the description.
1. Click on Continue.
1. Select the role: Project > Viewer.
1. Click on Continue.
1. Click on "Create Key".
1. Leave the default JSON selected.
1. Click on "Create".
1. The key will be downloaded to your machine.
1. Open the JSON key file, in a text editor and copy the Project Id, Client Email and Private Key values into the `index.js` file.
1. Enter the APIs & Services category.
1. Select Enable APIS & SERVICES at the top of the page
1. Search for DNS, then Select the option that appears and Enable it.
1. Enable all the APIs used to run scans, they are as follows: Stackdriver Monitoring, Stackdriver Logging, Compute, Cloud Key Management, Cloud SQL Admin, Kubernetes, Service Management, and Service Networking.