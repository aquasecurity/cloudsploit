# Writing CloudSploit Plugins

## Collection Phase
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

## Scanning Phase

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

## Result Codes
Each test has a result code that is used to determine if the test was successful and its risk level. The following codes are used:

* 0: PASS: No risks
* 1: WARN: The result represents a potential misconfiguration or issue but is not an immediate risk
* 2: FAIL: The result presents an immediate risk to the security of the account
* 3: UNKNOWN: The results could not be determined (API failure, wrong permissions, etc.)

## Tips for Writing Plugins
* Many security risks can be detected using the same API calls. To minimize the number of API calls being made, utilize the `cache` helper function to cache the results of an API call made in one test for future tests. For example, two plugins: "s3BucketPolicies" and "s3BucketPreventDelete" both call APIs to list every S3 bucket. These can be combined into a single plugin "s3Buckets" which exports two tests called "bucketPolicies" and "preventDelete". This way, the API is called once, but multiple tests are run on the same results.
* Ensure cloud infrastructure API calls are being used optimally. For example, call describeInstances with empty parameters to get all instances, instead of calling describeInstances multiple times looping through each instance name.
* Use async.eachLimit to reduce the number of simultaneous API calls. Instead of using a for loop on 100 requests, spread them out using async's each limit.

## Example
### AWS
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

### Azure
To more clearly illustrate writing a new plugin, let us consider the Virtual Machines VM Endpoint Protection plugin `plugins/azure/virtualmachines/vmEndpointProtection.js` . First, we know that we will need to query for a list of virtual machines via `virtualMachines:listAll`, then loop through each group and query for the more detailed set of data via `virtualMachineExtensions:list`.

We'll add these API calls to `collect.js`. First, under `calls` add:

```
virtualMachines: {
  listAll: {
    url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2019-12-01'
  }
},
```

Then, under `postcalls`, add:
```
virtualMachineExtensions: {
  list: {
    reliesOnPath: 'virtualMachines.listAll',
    properties: ['id'],
    url: 'https://management.azure.com/{id}/extensions?api-version=2019-12-01'
  }
},
```
CloudSploit will first get the list of virtual machines, then, it will loop through each one, using the virtual machine name to get more detailed info via `virtualMachineExtensions`.

Next, we'll write the plugin. Create a new file in the `plugins/virtualmachines` folder called `vmEndpointProtection.js` (this plugin already exists, but you can create a similar one for the purposes of this example).

In the file, we'll be sure to export the plugin's title, category, description, link, and more information about it. Additionally, we will add any API calls it makes:
```
apis: ['virtualMachines:listAll', 'virtualMachineExtensions:list'],
```
In the `run` function, we can obtain the output of the collection phase from earlier by doing:
```
var virtualMachines = helpers.addSource(cache, source, 
        ['virtualMachines', 'listAll', location]);
```
Then, we can loop through each of the results and do:
```
var virtualMachineExtensions = helpers.addSource(cache, source,     ['virtualMachineExtensions', 'list', location, virtualMachine.id]);
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

### GCP
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

### Oracle
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
