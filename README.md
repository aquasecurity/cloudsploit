[<img src="https://cloudsploit.com/images/logos/cloudsploit_by_aqua_A02.png" height="130">](https://cloudsploit.com)

[![Build Status](https://travis-ci.org/cloudsploit/scans.svg?branch=master)](https://travis-ci.org/cloudsploit/scans)
[![Known Vulnerabilities](https://snyk.io/test/github/cloudsploit/scans/badge.svg)](https://snyk.io/test/github/cloudsploit/scans)

CloudSploit Scans
=================

## Background
CloudSploit scans is an open-source project designed to allow detection of security risks in cloud infrastructure accounts. These scripts are designed to return a series of potential misconfigurations and security risks.

## Deploy your way
CloudSploit is available in two deployment options:

### Self-hosted
Follow the instructions below to deploy the open-source version of CloudSploit on your machine in just a few simple steps.

### Hosted at AquaCloud
CloudSploit, by Aqua, hosted in the Aqua Cloud, is a fully managed service maintained and updated by the cloud security experts at Aqua. Our hosted scanner handles the scheduling and running of background scans, aggregation of data into dashboards, tools, and visualizations, and integrates with popular third-party services for alerts.

Sign up to [AquaCloud](https://cloud.aquasec.com/signup) today!

## Installation
Ensure that NodeJS is installed. If not, install it from [here](https://nodejs.org/download/).

```
git clone git@github.com:cloudsploit/scans.git
```

```
npm install
```

## Configuration
To begin using the scanner, edit the `index.js` file with the corresponding settings. You can use any of these three options:
 * Enter your settings [inline](https://github.com/cloudsploit/scans/blob/master/index.js#L13-L53).
 * Create a json [file](https://github.com/cloudsploit/scans/blob/master/index.js#L57-L61).
 * Use [environment variables](https://github.com/cloudsploit/scans/blob/master/index.js#L64-L109). 

Cloud Infrastructure configuration steps:


* [AWS](#aws)
* [Azure](#azure) 
* [GCP](#gcp) 
* [Oracle](#oracle) 

#### AWS

Create a "cloudsploit" user, with the `SecurityAudit` policy.


1. Navigate to the [IAM console](https://console.aws.amazon.com/iam/home).
1. Go to Users 
1. Create a new user (Add user) 
1. Set the username to "cloudsploit" 
1. Set the access type to "Programmatic access", click Next.
1. Select one of your preferred options, if you have a group with SecurityAudit role assign the new user to that group.
1. If not select the "Attach existing policies directly" and select the SecurityAudit policy, click Next.
1. Set tags as needed and then click on "Create user".
1. Make sure you safely store the Access key ID and Secret access key.
1. Paste them into the corresponding AWS credentials section of the `index.js` file.

 
If using environment variables, the same ones expected by the aws sdks, namely `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`, can be used.

For more information on using our hosted scanner, [click here](#other-notes)

#### Azure

1. Log into your Azure Portal and navigate to the Azure Active Directory service.
1. Select App registrations and then click on New registration.
1. Enter "CloudSploit" and/or a descriptive name in the Name field, take note of it, it will be used again in step 3.
1. Leave the "Supported account types" default: "Accounts in this organizational directory only (YOURDIRECTORYNAME)".
1. Click on Register.
1. Copy the Application ID and Paste it below.
1. Copy the Directory ID and Paste it below.
1. Click on Certificates & secrets.
1. Under Client secrets, click on New client secret.
1. Enter a Description (i.e. Cloudsploit-2019) and select Expires "In 1 year".
1. Click on Add.
1. The Client secret value appears only once, make sure you store it safely.
1. Navigate to Subscriptions.
1. Click on the relevant Subscription ID, copy and paste the ID below.
1. Click on "Access Control (IAM)".
1. Go to the Role assignments tab.
1. Click on "Add", then "Add role assignment".
1. In the "Role" drop-down, select "Security Reader".
1. Leave the "Assign access to" default value.
1. In the "Select" drop-down, type the name of the app registration (e.g. "CloudSploit") you created and select it.
1. Click "Save".
1. Repeat the process for the role "Log Analytics Reader"

#### GCP

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

#### Oracle

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

## Running

To run a standard scan, showing all outputs and results, simply run:

```
node index.js
```

In the list of plugins in the `exports.js` file, comment out any plugins you do not wish to run. You can also skip entire regions by modifying the `skipRegions` array.


## Compliance

CloudSploit also supports mapping of its plugins to particular compliance policies. To run the compliance scan, use the `--compliance` flag. For example:
```
node index.js --compliance=hipaa
node index.js --compliance=pci
```

CloudSploit currently supports the following compliance mappings:

### HIPAA

HIPAA scans map CloudSploit plugins to the Health Insurance Portability and Accountability Act of 1996.

### PCI

PCI scans map CloudSploit plugins to the Payment Card Industry Data Security Standard.

## Output Formats

CloudSploit supports output in several formats for consumption by other tools.
If you do not specify otherwise, CloudSploit writes output to standard output
(the console). 

You can ignore results from output that return an OK status by passing a `--ignore-ok` commandline argument.

You can specify one or more output formats as follows:

```
# Output results in CSV (suppressing the console output)
node index.js --csv=./out.csv

# Output results in JSON (suppressing the console output)
node index.js --json=./out.json

# Output results in JUnit XML (suppressing the console output)
node index.js --junit=./out.xml

# Output results only to the console (default if omitted)
node index.js --console

# Output results in all supported formats
node index.js --console --junit=./out.xml --csv=./out.csv

# Output results in all supported formats for any test that is not OK.
node index.js --console --junit=./out.xml --csv=./out.csv --ignore-ok
```



## Architecture

CloudSploit works in two phases. First, it queries the cloud infrastructure APIs for various metadata about your account, namely the "collection" phase. Once all the necessary data is collected, the result is passed to the "scanning" phase. The scan uses the collected data to search for potential misconfigurations, risks, and other security issues, which are the resulting output.
## Writing a Plugin  

### Collection Phase  

To write a plugin, you want to understand which data is needed and how your cloud infrastructure provides them via their API calls. Once you have identified the API calls needed, you can add them to the collect.js file for your cloud infrastructure provider. This file determines the cloud infrastructure API calls and their run-order.

### Collectors

* [AWS Collection](#aws-collection)
* [Azure Collection](#azure-collection)
* [GCP Collection](#gcp-collection)
* [Oracle Collection](#oracle-collection)

#### AWS Collection

The following declaration tells the CloudSploit collection engine to query the CloudFront service using the `listDistributions` call and then save the results returned under `DistributionList.Items`.

```
CloudFront: {
  listDistributions: {
    property: 'DistributionList',
    secondProperty: 'Items'
  }
},
```

The second section in `collect.js` is `postcalls`, which is an array of objects defining API calls that rely on other calls first returned. For example, if you need to query for all `CloudFront distributions`, and then loop through each one and run a more detailed call, you would add the `CloudFront:listDistributions` call in the [`calls`](https://github.com/cloudsploit/scans/blob/master/collectors/aws/collector.js#L58-L64) section and then the more detailed call in [`postcalls`](https://github.com/cloudsploit/scans/blob/master/collectors/aws/collector.js#L467-L473), setting it to rely on the output of `listDistributions` call.

An example:  

```
getGroup: {
  reliesOnService: 'iam',
  reliesOnCall: 'listGroups',
  filterKey: 'GroupName',
  filterValue: 'GroupName'
},
```

This section tells CloudSploit to wait until the `IAM:listGroups` call has been made, and then loop through the data that is returned. The `filterKey` tells CloudSploit the name of the key from the original response, while `filterValue` tells it which property to set in the `getGroup` call filter. For example: `iam.getGroup({GroupName:abc})` where `abc` is the `GroupName` from the returned list. CloudSploit will loop through each response, re-invoking `getGroup` for each element.

You can find the [AWS Collector here.](https://github.com/cloudsploit/scans/blob/master/collectors/aws/collector.js)

#### Azure Collection

The following declaration tells the Cloudsploit collection engine to query the Compute Management Service using the virtualMachines:listAll call.

```
virtualMachines: {
  listAll: {
    api: "ComputeManagementClient",
    arm: true
  }
},
```

The second section in `collect.js` is `postcalls`, which is an array of objects defining API calls that rely on other calls first returned. For example, if you need to query for all `Virtual Machine instances`, and then loop through each one and run a more detailed call, you would add the `virtualMachines:listAll` call in the [`calls`](https://github.com/cloudsploit/scans/blob/master/collectors/azure/collector.js#L50-L55) section and then the more detailed call in [`postcalls`](https://github.com/cloudsploit/scans/blob/master/collectors/azure/collector.js#L293-L302), setting it to rely on the output of `listDistributions` call.

```
virtualMachineExtensions: {
  list: {
    api: "ComputeManagementClient",
    reliesOnService: ['resourceGroups', 'virtualMachines'],
    reliesOnCall: ['list', 'listAll'],
    filterKey: ['resourceGroupName', 'name'],
    filterValue: ['resourceGroupName', 'name'],
    arm: true
  }
},
```

You can find the [Azure Collector here.](https://github.com/cloudsploit/scans/blob/master/collectors/azure/collector.js)

#### GCP Collection

The following declaration tells the Cloudsploit collection engine to query the Compute Management Service using the buckets:list call.

```
buckets: {
  list: {
    api: 'storage',
    version: 'v1',
    location: null,
  }
},
```

The second section in `collect.js` is `postcalls`, which is an array of objects defining API calls that rely on other calls first returned. For example, if you need to query for all `Storage Buckets`, and then loop through each one and run a more detailed call, you would add the `buckets:list` call in the [`calls`](https://github.com/cloudsploit/scans/blob/master/collectors/google/collector.js#L103-L109) section and then the more detailed call in [`postcalls`](https://github.com/cloudsploit/scans/blob/master/collectors/google/collector.js#L213-L223), setting it to rely on the output of `getIamPolicy` call.

```
buckets: {
  getIamPolicy: {
    api: 'storage',
    version: 'v1',
    location: null,
    reliesOnService: ['buckets'],
    reliesOnCall: ['list'],
    filterKey: ['bucket'],
    filterValue: ['name'],
  }
},
```

You can find the [GCP Collector here.](https://github.com/cloudsploit/scans/blob/master/collectors/google/collector.js)

#### Oracle Collection

The following declaration tells the Cloudsploit collection engine to query the Compute Management Service using the vcn:list call.

```
vcn: {
  list: {
    api: "core",
    filterKey: ['compartmentId'],
    filterValue: ['compartmentId'],
  }
},
```

The second section in `collect.js` is `postcalls`, which is an array of objects defining API calls that rely on other calls first returned. For example, if you need to query for all `VCNs`, and then loop through each one and run a more detailed call, you would add the `vcn:list` call in the [`calls`](https://github.com/cloudsploit/scans/blob/master/collectors/oracle/collector.js#L41-L47) section and then the more detailed call in [`postcalls`](https://github.com/cloudsploit/scans/blob/master/collectors/oracle/collector.js#L243-L251), setting it to rely on the output of `get` call.

```
vcn: {
  get: {
    api: "core",
    reliesOnService: ['vcn'],
    reliesOnCall: ['list'],
    filterKey: ['vcnId'],
    filterValue: ['id'],
  }
},
```

You can find the [Oracle Collector here.](https://github.com/cloudsploit/scans/blob/master/collectors/oracle/collector.js)

### Scanning Phase

After the data has been collected, it is passed to the scanning engine when the results are analyzed for risks. Each plugin must export the following:

* Exports the following:
  * ```title``` (string): a user-friendly title for the plugin
  * ```category``` (string): the cloud infrastructure category (i.e.: **_AWS:_** EC2, RDS, ELB, etc. **_Azure:_** )
  * ```description``` (string): a description of what the plugin does
  * ```more_info``` (string): a more detailed description of the risk being tested for
  * ```link``` (string): an cloud infrastructure help URL describing the service or risk, preferably with mitigation methods
  * ```recommended_action``` (string): what the user should do to mitigate the risk found
  * ```run``` (function): a function that runs the test (see below)
* Accepts a ```collection``` object via the run function containing the full collection object obtained in the first phase.
* Calls back with the results and the data source.

### Result Codes
Each test has a result code that is used to determine if the test was successful and its risk level. The following codes are used:

* 0: PASS: No risks
* 1: WARN: The result represents a potential misconfiguration or issue but is not an immediate risk
* 2: FAIL: The result presents an immediate risk to the security of the account
* 3: UNKNOWN: The results could not be determined (API failure, wrong permissions, etc.)

### Tips for Writing Plugins
* Many security risks can be detected using the same API calls. To minimize the number of API calls being made, utilize the `cache` helper function to cache the results of an API call made in one test for future tests. For example, two plugins: "s3BucketPolicies" and "s3BucketPreventDelete" both call APIs to list every S3 bucket. These can be combined into a single plugin "s3Buckets" which exports two tests called "bucketPolicies" and "preventDelete". This way, the API is called once, but multiple tests are run on the same results.
* Ensure cloud infrastructure API calls are being used optimally. For example, call describeInstances with empty parameters to get all instances, instead of calling describeInstances multiple times looping through each instance name.
* Use async.eachLimit to reduce the number of simultaneous API calls. Instead of using a for loop on 100 requests, spread them out using async's each limit.

### Example
#### AWS
To more clearly illustrate writing a new plugin, let's consider the "IAM Empty Groups" plugin. First, we know that we will need to query for a list of groups via `listGroups`, then loop through each group and query for the more detailed set of data via `getGroup`.

We'll add these API calls to `collect.js`. First, under `calls` add:
```
IAM: {
  listGroups: {
    property: 'Groups'
  }
},
```
The `property` tells CloudSploit which property to read in the response from AWS.

Then, under `postCalls`, add:
```
IAM: {
  getGroup: {
    reliesOnService: 'iam',
    reliesOnCall: 'listGroups',
    filterKey: 'GroupName',
    filterValue: 'GroupName'
  }
},
```
CloudSploit will first get the list of groups, then, it will loop through each one, using the group name to get more detailed info via `getGroup`.

Next, we'll write the plugin. Create a new file in the `plugins/iam` folder called `emptyGroups.js` (this plugin already exists, but you can create a similar one for the purposes of this example).

In the file, we'll be sure to export the plugin's title, category, description, link, and more information about it. Additionally, we will add any API calls it makes:
```
apis: ['IAM:listGroups', 'IAM:getGroup'],
```
In the `run` function, we can obtain the output of the collection phase from earlier by doing:
```
var listGroups = helpers.addSource(cache, source,
        ['iam', 'listGroups', region]);
```
Then, we can loop through each of the results and do:
```
var getGroup = helpers.addSource(cache, source,
  ['iam', 'getGroup', region, group.GroupName]);
```
The `helpers` function ensures that the proper results are returned from the collection and that they are saved into a "source" variable which can be returned with the results.

Now, we can write the plugin functionality by checking for the data relevant to our requirements:
```
if (!getGroup || getGroup.err || !getGroup.data || !getGroup.data.Users) {
  helpers.addResult(results, 3, 'Unable to query for group: ' + group.GroupName, 'global', group.Arn);
} else if (!getGroup.data.Users.length) {
  helpers.addResult(results, 0, 'Group: ' + group.GroupName + ' does not contain any users', 'global', group.Arn);
  return cb();
} else {
  helpers.addResult(results, 0, 'Group: ' + group.GroupName + ' contains ' + getGroup.data.Users.length + ' user(s)', 'global', group.Arn);
}
```
The `addResult` function ensures we are adding the results to the `results` array in the proper format. This function accepts the following:
```
(results array, score, message, region, resource)
```
The `resource` is optional, and the `score` must be between 0 and 3 to indicate PASS, WARN, FAIL, or UNKNOWN.

#### Azure
To more clearly illustrate writing a new plugin, let us consider the Virtual Machines VM Endpoint Protection plugin `plugins/azure/virtualmachines/vmEndpointProtection.js` . First, we know that we will need to query for a list of virtual machines via `virtualMachines:listAll`, then loop through each group and query for the more detailed set of data via `virtualMachineExtensions:list`.

We'll add these API calls to `collect.js`. First, under `calls` add:

```
virtualMachines: {
  listAll: {
    api: "ComputeManagementClient",
    arm: true
  }
},
```

Then, under `postcalls`, add:
```
virtualMachineExtensions: {
  list: {
    api: "ComputeManagementClient",
    reliesOnService: ['resourceGroups', 'virtualMachines'],
    reliesOnCall: ['list', 'listAll'],
    filterKey: ['resourceGroupName', 'name'],
    filterValue: ['resourceGroupName', 'name'],
    arm: true
  }
},
```
CloudSploit will first get the list of virtual machines, then, it will loop through each one, using the virtual machine name to get more detailed info via `virtualMachineExtensions`.

Next, we'll write the plugin. Create a new file in the `plugins/virtualmachines` folder called `vmEndpointProtection.js` (this plugin already exists, but you can create a similar one for the purposes of this example).

In the file, we'll be sure to export the plugin's title, category, description, link, and more information about it. Additionally, we will add any API calls it makes:
```
apis: ['resourceGroups:list', 'virtualMachines:listAll', 'virtualMachineExtensions:list'],
```
In the `run` function, we can obtain the output of the collection phase from earlier by doing:
```
var virtualMachines = helpers.addSource(cache, source, 
        ['virtualMachines', 'listAll', location]);
```
Then, we can loop through each of the results and do:
```
var virtualMachineExtensions = helpers.addSource(cache, source,     ['virtualMachineExtensions', 'list', location]);
```
The `helpers` function ensures that the proper results are returned from the collection and that they are saved into a "source" variable which can be returned with the results.

Now, we can write the plugin functionality by checking for the data relevant to our requirements:
```
if (virtualMachineExtensions.err || !virtualMachineExtensions.data) {
    helpers.addResult(results, 3, 
        Unable to query for VM Extensions: ' + helpers.addError(virtualMachineExtensions), location);
                return rcb();
}
if (!virtualMachineExtensions.data.length) {
    helpers.addResult(results, 0, 'No VM Extensions found', location);
}
```
The `addResult` function ensures we are adding the results to the `results` array in the proper format. This function accepts the following:
```
(results array, score, message, region, resource)
```
The `resource` is optional, and the `score` must be between 0 and 3 to indicate PASS, WARN, FAIL, or UNKNOWN.

#### GCP
To more clearly illustrate writing a new plugin, let us consider the Storage Bucket All Users Policy plugin `plugins/google/storage/bucketAllUsersPolicy.js` . First, we know that we will need to query for a list of buckets via `buckets:list`, then loop through each group and query for the more detailed set of data via `buckets:getIamPolicy`.

We'll add these API calls to `collect.js`. First, under `calls` add:

```
buckets: {
  list: {
    api: 'storage',
    version: 'v1',
    location: null,
  }
},
```

Then, under `postcalls`, add:
```
buckets: {
  getIamPolicy: {
    api: 'storage',
    version: 'v1',
    location: null,
    reliesOnService: ['buckets'],
    reliesOnCall: ['list'],
    filterKey: ['bucket'],
    filterValue: ['name'],
  }
},
```
CloudSploit will first get the list of buckets, then, it will loop through each one, using the bucket name to get more detailed info via `getIamPolicy`.

Next, we'll write the plugin. Create a new file in the `plugins/google/storage` folder called `bucketAllUsersPolicy.js` (this plugin already exists, but you can create a similar one for the purposes of this example).

In the file, we'll be sure to export the plugin's title, category, description, link, and more information about it. Additionally, we will add any API calls it makes:
```
apis: ['buckets:list', 'buckets:getIamPolicy'],
```
In the `run` function, we can obtain the output of the collection phase from earlier by doing:
```
let bucketPolicyPolicies = helpers.addSource(cache, source, 
            ['buckets', 'getIamPolicy', region]);
```
The `helpers` function ensures that the proper results are returned from the collection and that they are saved into a "source" variable which can be returned with the results.

Now, we can write the plugin functionality by checking for the data relevant to our requirements:
```
if (bucketPolicyPolicies.err || !bucketPolicyPolicies.data) {
  helpers.addResult(results, 3, 'Unable to query storage buckets: ' + helpers.addError(bucketPolicyPolicies), region);
  return rcb();
}

if (!bucketPolicyPolicies.data.length) {
  helpers.addResult(results, 0, 'No storage buckets found', region);
  return rcb();
}
```
The `addResult` function ensures we are adding the results to the `results` array in the proper format. This function accepts the following:
```
(results array, score, message, region, resource)
```
The `resource` is optional, and the `score` must be between 0 and 3 to indicate PASS, WARN, FAIL, or UNKNOWN.

#### Oracle
To more clearly illustrate writing a new plugin, let us consider the Networking Subnet Multi AD plugin `plugins/oracle/networking/subnetMultiAd.js` . First, we know that we will need to query for a list of VCNs via `vcn:list`, then loop through each group and query for the more detailed set of data via `subnet:list`.

We'll add these API calls to `collect.js`. First, under `calls` add:

```
vcn: {
  list: {
    api: "core",
    filterKey: ['compartmentId'],
    filterValue: ['compartmentId'],
  }
},
```

Then, under `postcalls`, add:
```
subnet: {
  list: {
    api: "core",
    reliesOnService: ['vcn'],
    reliesOnCall: ['list'],
    filterKey: ['compartmentId', 'vcnId'],
    filterValue: ['compartmentId', 'id'],
    filterConfig: [true, false],
  }
},
```
CloudSploit will first get the list of vcns, then, it will loop through each one, using the vcn id to get more detailed info via `subnet:list`.

Next, we'll write the plugin. Create a new file in the `plugins/oracle/networking` folder called `subnetMultiAd.js` (this plugin already exists, but you can create a similar one for the purposes of this example).

In the file, we'll be sure to export the plugin's title, category, description, link, and more information about it. Additionally, we will add any API calls it makes:
```
apis: ['vcn:list','subnet:list']
```
In the `run` function, we can obtain the output of the collection phase from earlier by doing:
```
var subnets = helpers.addSource(cache, source,
                    ['subnet', 'list', region]);
```
The `helpers` function ensures that the proper results are returned from the collection and that they are saved into a "source" variable which can be returned with the results.

Now, we can write the plugin functionality by checking for the data relevant to our requirements:
```
if ((subnets.err && subnets.err.length) || !subnets.data) {
  helpers.addResult(results, 3,
    'Unable to query for subnets: ' + helpers.addError(subnets), region);
  return rcb();
}

if (!subnets.data.length) {
  helpers.addResult(results, 0, 'No subnets found', region);
  return rcb();
}
```
The `addResult` function ensures we are adding the results to the `results` array in the proper format. This function accepts the following:
```
(results array, score, message, region, resource)
```
The `resource` is optional, and the `score` must be between 0 and 3 to indicate PASS, WARN, FAIL, or UNKNOWN.

## Other Notes

When using the [hosted scanner](https://cloudsploit.com/scan), you will be able to see an intuitive visual representation of the scan results. In CloudSploit's console, printable scan results look as follows:

[<img src="https://cloudsploit.com/images/printable-report.png">](https://console.cloudsploit.com/signup)

### Cross-account IAM role

Cross-account roles enable you to share access to your account with another AWS account using the same policy model that you're used to within AWS services' scope.
 
The advantage is that cross-account roles are much more secure than key-based access, since an attacker who steals a cross-account role ARN still cannot make API calls unless he/she also infiltrates the AWS account that has been authorized to use the role in question.

To create a cross-account role:

```
1. Navigate to the [IAM console](https://console.aws.amazon.com/iam/home).
2. Log into your AWS account and navigate to the IAM console.
3. Create a new IAM role.
4. When prompted for a trusted entity select: "Another AWS account".
5. Enter "057012691312" for the account to trust (Account ID).
6. Check the box to "Require external ID" and enter the external ID displayed below.
7. Ensure that MFA token is not selected.
8. Select the "SecurityAudit" managed policy.
9. Enter a memorable role name and create the role.
10. Then click on the role name and copy the role ARN for use in the next step.
```

### CloudSploit Supplemental Policy
Allows read only accesss to services not included in the SecurityAudit AWS Managed policy but that are also tested by the CSPM scans.

```$xslt
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ses:DescribeActiveReceiptRuleSet",
                "athena:GetWorkGroup",
                "logs:DescribeLogGroups",
                "logs:DescribeMetricFilters",
                "elastictranscoder:ListPipelines",
                "elasticfilesystem:DescribeFileSystems",
                "servicequotas:ListServiceQuotas"
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}
```
### AWS Inline Policy (Not Recommended)

If you'd prefer to be more restrictive, the following IAM policy contains the exact permissions used by the scan.

**WARNING:** This policy will likely change as more plugins are written. If a test returns "UNKNOWN" it is likely missing a required permission. The preferred method is to use the "SecurityAudit" policy.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Resource": "*",
            "Action": [
                "acm:Describe*",
                "acm:List*",
                "application-autoscaling:Describe*",
                "appmesh:Describe*",
                "appmesh:List*",
                "appsync:List*",
                "athena:List*",
                "athena:GetWorkGroup",
                "autoscaling:Describe*",
                "batch:DescribeComputeEnvironments",
                "batch:DescribeJobDefinitions",
                "chime:List*",
                "cloud9:Describe*",
                "cloud9:ListEnvironments",
                "clouddirectory:ListDirectories",
                "cloudformation:DescribeStack*",
                "cloudformation:GetTemplate",
                "cloudformation:ListStack*",
                "cloudformation:GetStackPolicy",
                "cloudfront:Get*",
                "cloudfront:List*",
                "cloudhsm:ListHapgs",
                "cloudhsm:ListHsms",
                "cloudhsm:ListLunaClients",
                "cloudsearch:DescribeDomains",
                "cloudsearch:DescribeServiceAccessPolicies",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetEventSelectors",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:ListTags",
                "cloudtrail:LookupEvents",
                "cloudwatch:Describe*",
                "codebuild:ListProjects",
                "codecommit:BatchGetRepositories",
                "codecommit:GetBranch",
                "codecommit:GetObjectIdentifier",
                "codecommit:GetRepository",
                "codecommit:List*",
                "codedeploy:Batch*",
                "codedeploy:Get*",
                "codedeploy:List*",
                "codepipeline:ListPipelines",
                "codestar:Describe*",
                "codestar:List*",
                "cognito-identity:ListIdentityPools",
                "cognito-idp:ListUserPools",
                "cognito-sync:Describe*",
                "cognito-sync:List*",
                "comprehend:Describe*",
                "comprehend:List*",
                "config:BatchGetAggregateResourceConfig",
                "config:BatchGetResourceConfig",
                "config:Deliver*",
                "config:Describe*",
                "config:Get*",
                "config:List*",
                "datapipeline:DescribeObjects",
                "datapipeline:DescribePipelines",
                "datapipeline:EvaluateExpression",
                "datapipeline:GetPipelineDefinition",
                "datapipeline:ListPipelines",
                "datapipeline:QueryObjects",
                "datapipeline:ValidatePipelineDefinition",
                "datasync:Describe*",
                "datasync:List*",
                "dax:Describe*",
                "dax:ListTags",
                "directconnect:Describe*",
                "dms:Describe*",
                "dms:ListTagsForResource",
                "ds:DescribeDirectories",
                "dynamodb:DescribeContinuousBackups",
                "dynamodb:DescribeGlobalTable",
                "dynamodb:DescribeTable",
                "dynamodb:DescribeTimeToLive",
                "dynamodb:ListBackups",
                "dynamodb:ListGlobalTables",
                "dynamodb:ListStreams",
                "dynamodb:ListTables",
                "ec2:Describe*",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "ecs:Describe*",
                "ecs:List*",
                "eks:DescribeCluster",
                "eks:ListClusters",
                "elasticache:Describe*",
                "elasticbeanstalk:Describe*",
                "elasticfilesystem:DescribeFileSystems",
                "elasticfilesystem:DescribeMountTargetSecurityGroups",
                "elasticfilesystem:DescribeMountTargets",
                "elasticloadbalancing:Describe*",
                "elasticmapreduce:Describe*",
                "elasticmapreduce:ListClusters",
                "elasticmapreduce:ListInstances",
                "elastictranscoder:ListPipelines",
                "es:Describe*",
                "es:ListDomainNames",
                "events:Describe*",
                "events:List*",
                "firehose:Describe*",
                "firehose:List*",
                "fms:ListComplianceStatus",
                "fms:ListPolicies",
                "fsx:Describe*",
                "fsx:List*",
                "gamelift:ListBuilds",
                "gamelift:ListFleets",
                "glacier:DescribeVault",
                "glacier:GetVaultAccessPolicy",
                "glacier:ListVaults",
                "globalaccelerator:Describe*",
                "globalaccelerator:List*",
                "greengrass:List*",
                "guardduty:Get*",
                "guardduty:List*",
                "iam:GenerateCredentialReport",
                "iam:GenerateServiceLastAccessedDetails",
                "iam:Get*",
                "iam:List*",
                "iam:SimulateCustomPolicy",
                "iam:SimulatePrincipalPolicy",
                "inspector:Describe*",
                "inspector:Get*",
                "inspector:List*",
                "inspector:Preview*",
                "iot:Describe*",
                "iot:GetPolicy",
                "iot:GetPolicyVersion",
                "iot:List*",
                "kinesis:DescribeStream",
                "kinesis:ListStreams",
                "kinesis:ListTagsForStream",
                "kinesisanalytics:ListApplications",
                "kms:Describe*",
                "kms:Get*",
                "kms:List*",
                "lambda:GetAccountSettings",
                "lambda:GetFunctionConfiguration",
                "lambda:GetLayerVersionPolicy",
                "lambda:GetPolicy",
                "lambda:List*",
                "license-manager:List*",
                "lightsail:GetInstances",
                "lightsail:GetLoadBalancers",
                "logs:Describe*",
                "logs:ListTagsLogGroup",
                "machinelearning:DescribeMLModels",
                "mediaconnect:Describe*",
                "mediaconnect:List*",
                "mediastore:GetContainerPolicy",
                "mediastore:ListContainers",
                "opsworks:DescribeStacks",
                "opsworks-cm:DescribeServers",
                "organizations:List*",
                "organizations:Describe*",
                "quicksight:Describe*",
                "quicksight:List*",
                "ram:List*",
                "rds:Describe*",
                "rds:DownloadDBLogFilePortion",
                "rds:ListTagsForResource",
                "redshift:Describe*",
                "rekognition:Describe*",
                "rekognition:List*",
                "robomaker:Describe*",
                "robomaker:List*",
                "route53:Get*",
                "route53:List*",
                "route53domains:GetDomainDetail",
                "route53domains:GetOperationDetail",
                "route53domains:ListDomains",
                "route53domains:ListOperations",
                "route53domains:ListTagsForDomain",
                "route53resolver:List*",
                "route53resolver:Get*",
                "s3:GetAccelerateConfiguration",
                "s3:GetAccountPublicAccessBlock",
                "s3:GetAnalyticsConfiguration",
                "s3:GetBucket*",
                "s3:GetEncryptionConfiguration",
                "s3:GetInventoryConfiguration",
                "s3:GetLifecycleConfiguration",
                "s3:GetMetricsConfiguration",
                "s3:GetObjectAcl",
                "s3:GetObjectVersionAcl",
                "s3:GetReplicationConfiguration",
                "s3:ListAllMyBuckets",
                "sagemaker:Describe*",
                "sagemaker:List*",
                "sdb:DomainMetadata",
                "sdb:ListDomains",
                "secretsmanager:GetResourcePolicy",
                "secretsmanager:ListSecrets",
                "secretsmanager:ListSecretVersionIds",
                "securityhub:Describe*",
                "securityhub:Get*",
                "securityhub:List*",
                "serverlessrepo:GetApplicationPolicy",
                "serverlessrepo:List*",
                "servicequotas:ListServiceQuotas",
                "ses:GetIdentityDkimAttributes",
                "ses:GetIdentityPolicies",
                "ses:GetIdentityVerificationAttributes",
                "ses:ListIdentities",
                "ses:ListIdentityPolicies",
                "ses:ListVerifiedEmailAddresses",
                "ses:DescribeActiveReceiptRuleSet",
                "shield:Describe*",
                "shield:List*",
                "snowball:ListClusters",
                "snowball:ListJobs",
                "sns:GetTopicAttributes",
                "sns:ListSubscriptionsByTopic",
                "sns:ListTopics",
                "sqs:GetQueueAttributes",
                "sqs:ListDeadLetterSourceQueues",
                "sqs:ListQueues",
                "sqs:ListQueueTags",
                "ssm:Describe*",
                "ssm:GetAutomationExecution",
                "ssm:ListDocuments",
                "sso:DescribePermissionsPolicies",
                "sso:List*",
                "states:ListStateMachines",
                "storagegateway:DescribeBandwidthRateLimit",
                "storagegateway:DescribeCache",
                "storagegateway:DescribeCachediSCSIVolumes",
                "storagegateway:DescribeGatewayInformation",
                "storagegateway:DescribeMaintenanceStartTime",
                "storagegateway:DescribeNFSFileShares",
                "storagegateway:DescribeSnapshotSchedule",
                "storagegateway:DescribeStorediSCSIVolumes",
                "storagegateway:DescribeTapeArchives",
                "storagegateway:DescribeTapeRecoveryPoints",
                "storagegateway:DescribeTapes",
                "storagegateway:DescribeUploadBuffer",
                "storagegateway:DescribeVTLDevices",
                "storagegateway:DescribeWorkingStorage",
                "storagegateway:List*",
                "tag:GetResources",
                "tag:GetTagKeys",
                "transfer:Describe*",
                "transfer:List*",
                "translate:List*",
                "trustedadvisor:Describe*",
                "waf:ListWebACLs",
                "waf-regional:ListWebACLs",
                "workspaces:Describe*",
                "xray:Get*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "apigateway:GET"
            ],
            "Resource": [
                "arn:aws:apigateway:*::/apis",
                "arn:aws:apigateway:*::/apis/*/stages",
                "arn:aws:apigateway:*::/apis/*/stages/*",
                "arn:aws:apigateway:*::/apis/*/routes",
                "arn:aws:apigateway:*::/restapis",
                "arn:aws:apigateway:*::/restapis/*/authorizers",
                "arn:aws:apigateway:*::/restapis/*/authorizers/*",
                "arn:aws:apigateway:*::/restapis/*/documentation/versions",
                "arn:aws:apigateway:*::/restapis/*/resources",
                "arn:aws:apigateway:*::/restapis/*/resources/*",
                "arn:aws:apigateway:*::/restapis/*/resources/*/methods/*",
                "arn:aws:apigateway:*::/restapis/*/stages",
                "arn:aws:apigateway:*::/restapis/*/stages/*",
                "arn:aws:apigateway:*::/vpclinks"
            ]
        }
    ]
}
```
