[![CloudSploit](https://cloudsploit.com/img/logo-big-text-100.png "CloudSploit")](https://cloudsploit.com)

CloudSploit Scans
=================

## Background
CloudSploit scans is an open-source project designed to allow detection of security risks in an AWS account. These scripts are designed to run against an AWS account and return a series of potential misconfigurations and security risks.

## Installation
Ensure that NodeJS is installed. If not, install it from [here](https://nodejs.org/download/).

```
git clone git@github.com:cloudsploit/scans.git
```

```
npm install
```

## Setup
To begin using the scanner, edit the `index.js` file with your AWS key, secret, and optionally (for temporary credentials), a session token. You can also set a file containing credentials. To determine the permissions associated with your credentials, see the [permissions section below](#permissions). In the list of plugins in the `exports.js` file, comment out any plugins you do not wish to run. You can also skip entire regions by modifying the `skipRegions` array.

### Cross Account Roles
When using the [hosted scanner](https://cloudsploit.com/scan), you'll need to create a cross-account IAM role. Cross-account roles enable you to share access to your account with another AWS account using the same policy model that you're used to. The advantage is that cross-account roles are much more secure than key-based access, since an attacker who steals a cross-account role ARN still can't make API calls unless they also infiltrate the authorized AWS account.

To create a cross-account role:

1. Navigate to the [IAM console](https://console.aws.amazon.com/iam/home).
2. Click "Roles" and then "Create New Role".
3. Provide a role name (suggested "cloudsploit").
4. Select the "Role for Cross-Account Access" radio button.
5. Click the "Select" button next to "Allows IAM users from a 3rd party AWS account to access this account."
6. Enter `057012691312` for the account ID (this is the ID of CloudSploit's AWS account).
7. Copy the auto-generated external ID from the CloudSploit web page and paste it into the AWS IAM console textbox.
8. Ensure that "Require MFA" is _not_ selected.
9. Click "Next Step".
10. Select the "Security Audit" policy. Then click "Next Step" again.
11. Click through to create the role.

## Permissions
The scans require read-only permissions to your account. This can be done by adding the "Security Audit" AWS managed policy to your IAM user or role.

### Security Audit Managed Policy (Recommended)

To configure the managed policy:

1. Open the [IAM Console](https://console.aws.amazon.com/iam/home).
2. Find your user or role.
3. Click the "Permissions" tab.
4. Under "Managed Policy", click "Attach policy".
5. In the filter box, enter "Security Audit"
6. Select the "Security Audit" policy and save.

### Inline Policy (Not Recommended)

If you'd prefer to be more restrictive, the following IAM policy contains the exact permissions used by the scan.

WARNING: This policy will likely change as more plugins are written. If a test returns "UNKNOWN" it is likely missing a required permission. The preferred method is to use the "Security Audit" policy.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
            "cloudfront:ListDistributions",
            "cloudtrail:DescribeTrails",
            "configservice:DescribeConfigurationRecorders",
            "configservice:DescribeConfigurationRecorderStatus",
            "ec2:DescribeInstances",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeAccountAttributes",
            "ec2:DescribeAddresses",
            "ec2:DescribeVpcs",
            "ec2:DescribeFlowLogs",
            "ec2:DescribeSubnets",
            "elasticloadbalancing:DescribeLoadBalancerPolicies",
            "elasticloadbalancing:DescribeLoadBalancers",
            "iam:GenerateCredentialReport",
            "iam:ListServerCertificates",
            "iam:ListGroups",
            "iam:GetGroup",
            "iam:GetAccountPasswordPolicy",
            "iam:ListUsers",
            "iam:ListUserPolicies",
            "iam:ListAttachedUserPolicies",
            "kms:ListKeys",
            "kms:DescribeKey",
            "kms:GetKeyRotationStatus",
            "rds:DescribeDBInstances",
            "rds:DescribeDBClusters",
            "route53domains:ListDomains",
            "s3:GetBucketVersioning",
            "s3:GetBucketLogging",
            "s3:GetBucketAcl",
            "s3:ListBuckets",
            "ses:ListIdentities",
            "ses:getIdentityDkimAttributes"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

## Running

To run a standard scan, showing all outputs and results, simply run:

```
node index.js
```

## Optional Plugins

Some plugins may require additional permissions not outlined above. Since their required IAM permissions are not included in the `SecurityAudit` managed policy, these plugins are not included in the `exports.js` file by default. To enable these plugins, uncomment them from the `exports.js` file, if applicable, add the policies required to an inline IAM policy, and re-run the scan.

## Architecture

CloudSploit works in two phases. First, it queries the AWS APIs for various metadata about your account. This is known as the "collection" phase. Once all the necessary data has been collected, the result is passed to the second phase - "scanning." The scan uses the collected data to search for potential misconfigurations, risks, and other security issues. These are then provided as output.

## Writing a Plugin
### Collection Phase
To write a plugin, you must understand what AWS API calls your scan makes. These must be added to the `collect.js` file. This file determines the AWS API calls and the order in which they are made. For example:
```
CloudFront: {
  listDistributions: {
    property: 'DistributionList',
    secondProperty: 'Items'
  }
},
```
This declaration tells the CloudSploit collection engine to query the CloudFront service using the `listDistributions` call and then save the results returned under `DistributionList.Items`.

The second section in `collect.js` is `postcalls`, which is an array of objects defining API calls that rely on other calls being returned first. For example, if you need to first query for all EC2 instances, and then loop through each instance and run a more detailed call, you would add the `EC2:DescribeInstances` call in the first `calls` section and then add the more detailed call in `postCalls` setting it to rely on the output of `DescribeInstances`.

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

### Scanning Phase
After the data has been collected, it is passed to the scanning engine when the results are analyzed for risks. Each plugin must export the following:

* Exports the following:
  * ```title``` (string): a user-friendly title for the plugin
  * ```category``` (string): the AWS category (EC2, RDS, ELB, etc.)
  * ```description``` (string): a description of what the plugin does
  * ```more_info``` (string): a more detailed description of the risk being tested for
  * ```link``` (string): an AWS help URL describing the service or risk, preferably with mitigation methods
  * ```recommended_action``` (string): what the user should do to mitigate the risk found
  * ```run``` (function): a function that runs the test (see below)
* Accepts a ```collection``` object via the run function containing the full collection object obtained in the first phase.
* Calls back with the results and the data source.

### Result Codes
Each test has a result code that is used to determine if the test was successful and its risk level. The following codes are used:

* 0: OKAY: No risks
* 1: WARN: The result represents a potential misconfiguration or issue but is not an immediate risk
* 2: FAIL: The result presents an immediate risk to the security of the account
* 3: UNKNOWN: The results could not be determined (API failure, wrong permissions, etc.)

### Tips for Writing Plugins
* Many security risks can be detected using the same API calls. To minimize the number of API calls being made, utilize the `cache` helper function to cache the results of an API call made in one test for future tests. For example, two plugins: "s3BucketPolicies" and "s3BucketPreventDelete" both call APIs to list every S3 bucket. These can be combined into a single plugin "s3Buckets" which exports two tests called "bucketPolicies" and "preventDelete". This way, the API is called once, but multiple tests are run on the same results.
* Ensure AWS API calls are being used optimally. For example, call describeInstances with empty parameters to get all instances, instead of calling describeInstances multiple times looping through each instance name.
* Use async.eachLimit to reduce the number of simultaneous API calls. Instead of using a for loop on 100 requests, spread them out using async's each limit.

### Example
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
  helpers.addResult(results, 1, 'Group: ' + group.GroupName + ' does not contain any users', 'global', group.Arn);
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
