var expect = require('chai').expect;
const notebookCmkEncrypted = require('./notebookCmkEncrypted');

const listNotebookInstances = [
    {
        "NotebookInstanceName": "nb-instance-2",
        "NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:112233445566:notebook-instance/nb-instance-2",
        "NotebookInstanceStatus": "InService",
        "Url": "nb-instance-2.notebook.us-east-1.sagemaker.aws",
        "InstanceType": "ml.t2.medium",
        "CreationTime": "2020-11-16T14:59:14.821Z",
        "LastModifiedTime": "2020-11-16T14:59:21.692Z",      
    },
    {
        "NotebookInstanceName": "nb-instance-3",
        "NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:112233445566:notebook-instance/nb-instance-3",
        "NotebookInstanceStatus": "InService",
        "DirectInternetAccess": "Enabled",
        "Url": "nb-instance-2.notebook.us-east-1.sagemaker.aws",
        "InstanceType": "ml.t2.medium",
    }
];

const describeNotebookInstance = [
    {
        "NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:1122334455:notebook-instance/test",
        "NotebookInstanceName": "test",
        "NotebookInstanceStatus": "Pending",
        "Url": "test-mdbp.notebook.us-east-1.sagemaker.aws",
        "InstanceType": "ml.t3.medium",
        "SubnetId": "subnet-090543c3cc7bee455",
        "SecurityGroups": [
            "sg-0931c3a02deed68f5"
        ],
        "RoleArn": "arn:aws:iam::11222333445:role/service-role/AmazonSageMaker-ExecutionRole-20230803T155360",
        "NetworkInterfaceId": "eni-0fce758c1693daae7",
        "KmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
        "LastModifiedTime": "2023-08-04T12:59:53.661000+05:00",
        "CreationTime": "2023-08-04T12:59:46.521000+05:00",
        "DirectInternetAccess": "Disabled",
        "VolumeSizeInGB": 5,
        "RootAccess": "Enabled",
        "PlatformIdentifier": "notebook-al2-v2",
        "InstanceMetadataServiceConfiguration": {
            "MinimumInstanceMetadataServiceVersion": "2"
        }
    },
    {
        "NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:11222334455:notebook-instance/test",
        "NotebookInstanceName": "test",
        "NotebookInstanceStatus": "Pending",
        "Url": "test-mdbp.notebook.us-east-1.sagemaker.aws",
        "InstanceType": "ml.t3.medium",
        "SecurityGroups": [
            "sg-0931c3a02deed68f5"
        ],
        "RoleArn": "arn:aws:iam::1122334455:role/service-role/AmazonSageMaker-ExecutionRole-20230803T155360",
        "LastModifiedTime": "2023-08-04T12:59:53.661000+05:00",
        "CreationTime": "2023-08-04T12:59:46.521000+05:00",
        "DirectInternetAccess": "Disabled",
        "VolumeSizeInGB": 5,
        "RootAccess": "Enabled",
        "PlatformIdentifier": "notebook-al2-v2",
        "InstanceMetadataServiceConfiguration": {
            "MinimumInstanceMetadataServiceVersion": "2"
        }
    }


];
const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0252",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0252",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "AWS",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    }
];

const listKeys = [
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
    },
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/f4942dd6-bce5-4213-bdd3-cc8ccd87dd890"
    }
]

const createCache = (listInstances, instances, keys, describeKey, listInstancesErr, instancesErr, keysErr, describeKeyErr) => {
    var name = (listInstances && listInstances.length) ? listInstances[0].NotebookInstanceName : null;
    var keyId = (keys && keys.length) ? keys[0].KeyArn.split('/')[1] : null;
    return {
        sagemaker: {
            listNotebookInstances: {
                'us-east-1': {
                    data: listInstances,
                    err: listInstancesErr
                }
            },
            describeNotebookInstance: {
                'us-east-1': {
                    [name] : {
                        data: instances,
                        err: instancesErr
                    }
                }
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: keys,
                    err: keysErr
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        err: describeKeyErr,
                        data: describeKey
                    },
                },
            },
        }

    };
};



describe('notebookCmkEncrypted', function() {
    describe('run', function () {
        it('should PASS if instance is encrypted with cmk', function(done) {
            const cache = createCache([listNotebookInstances[0]],describeNotebookInstance[0], listKeys, describeKey[0]);
            notebookCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if instance is not encrypted with cmk', function(done) {
            const cache = createCache([listNotebookInstances[1]],describeNotebookInstance[1],listKeys, describeKey[0]);
            notebookCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Notebook instances found', function (done) {
            const cache = createCache([]);
            notebookCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Notebook Instances Found');
                done();
            });
        });

        it('should UNKNOWN if unable to list Notebook instances', function (done) {
            const cache = createCache(null, null, null, null, { message: "Unable to query for Notebook Instances" });
            notebookCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Notebook Instances: ');
                done();
            });
        });

        
    });
});
