# Writing CloudSploit Remediation
To write remediation for a plugin, you need to understand what action needs to be performed to remediate the plugin, what permissions are needed from the cloud provider, and what is the api call you need to make to perform that action. You need to understand what all data are needed to perform this. Those api calls to collect the data should be added in the collect.js for the particluar cloud provider, if those are not there already. For more information on collectors please check [complete guide](docs/writing-plugins.md).
### Remediations

* [AWS Remediation](#aws-remediation)
* [Azure Remediation](#azure-remediation)
* [GCP Remediation](#gcp-remediation)
* [Oracle Remediation](#oracle-remediation)

### Prerequisites
Please go through the collector and scanning doc [here](docs/writing-plugins.md) before developing remediation to understand how data is being collected from csp and results are stored.

#### AWS Remediation
To remediate a plugin we need to specify following things in exports section:
```
remediation_description: 'The impacted bucket will be configured to be have Versioning enabled.',
remediation_min_version: '202010160030',
apis_remediate: ['S3:listBuckets', 'S3:getBucketVersioning', 'S3:getBucketLocation'],
actions: {
    remediate: ['S3:putBucketVersioning'],
    rollback: ['S3:putBucketVersioning'],
},
permissions: {
    remediate: ['s3:PutBucketVersioning'],
    rollback: ['s3:PutBucketVersioning']
},
realtime_triggers: ['s3:CreateBucket'],
```
##### Description of the fields mentioned above:
* ```remediation_description```(string): A short description on what action will be performed to remediate the vulnerability.
* ```remediation_min_version```(string): Timestamp when this remediation is available in `YYYYMMDDhhmm` format.
* ```apis_remediate```(string): These are the api calls to collect the data needed for remediation.
* ```actions```(dictionary): Here we need to mention the following
    * ```remediate```(list): The actual api calls to perform the remediate action.
    * ```rollback```(list): The api calls to perform rollback to undo the remediation.
* ```permissions```(dictionary): Permission needed from cloud provider.
    * ```remediate```(list): The permissions to perform the remediate action.
    * ```rollback```(list): The permissions to perform rollback to undo the remediation.
* ```realtime_triggers```(list):  The action which will trigger this remediation automatically. 
* ```remediate: function(config, cache, settings, resource, callback)```: This is the function which will have the main logic to remediate. We will discuss this in more detail in [Remediate Function](#remediate-function) section.
* ```rollback: function(config, cache, settings, resource, callback)```: This is to rollback the remediate action

Above is the example from s3/bucketVersioning plugin
##### Remediate Function
In ```remediate``` function we will receive the following inputs as parameter.
* ```config```: This will have the needed info to call aws sdk.
* ```cache``` : This will have the collection data.
* ```settings```: This object will have user given inputs. This also will store the action data for logging purpose.
* ```callback```: call back function.

The inputs will be passed from engine.js. In enjine.js after the scan is complete we have all the data and result.
Now based on the result and the plugin names passed with ```--remediate``` in cli remediaion will be called.

```
if (settings.remediate && settings.remediate.length) {
    if (settings.remediate.indexOf(key) > -1) {
        if (results[r].status === 2) {
            var resource = results[r].resource;
            var event = {};
            event['remediation_file'] = {};
            event['remediation_file'] = initializeFile(event['remediation_file'], 'execute', key, resource);
            plugin.remediate(cloudConfig, collection, event, resource, (err, result) => {
                if (err) return console.log(err);
                return console.log(result);
            });
        }
    }
 }
```
If the remediation action takes an input we need to pass it in ```event['input']```. Like for bucketEncrption we can have keys from user as

```
"input": {
    "kmsKeyId": "110f0e35-eabc-466c-b884-e45356daa12d"
    }
```
So we need to do 
```
event['input'] = {
        "kmsKeyId": "110f0e35-eabc-466c-b884-e45356daa12d"
       }
```
This event will be passed as ```settings``` to the remediate call. **Document the regex and a short description of the custom inputs**.
And then in remediate function we need to pass this to the parameter that actual sdk call expects.

```
if (settings.input &&
    settings.input.kmsKeyId) {
    params = {
        'Bucket': bucketName,
        'ServerSideEncryptionConfiguration': {
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': config.kmsKeyId
                }
            }]
        }
    };
} else {
    params = {
        'Bucket': bucketName,
        'ServerSideEncryptionConfiguration': {
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256',
                }
            }]
        }
    };
}
```
For more details please check the [bucketEncryption plugin here](https://github.com/aquasecurity/cloudsploit/blob/master/plugins/aws/s3/bucketEncryption.js)
#### Azure Remediation

TBD

#### GCP Collection

TBD

#### Oracle Collection

TBD
 