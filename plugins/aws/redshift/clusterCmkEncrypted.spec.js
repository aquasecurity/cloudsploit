const expect = require('chai').expect;
const clusterCmkEncrypted = require('./clusterCmkEncrypted');

const clusters = [
    {
        "ClusterIdentifier": "redshift-cluster1-124",    
        "NodeType": "dc2.large",
        "ClusterStatus": "available",
        "ClusterAvailabilityStatus": "Available",
        "MasterUsername": "awsuser",
        "DBName": "dev",
        "Endpoint": {
            "Address": "redshift-cluster1-124.cks44thktt7l.us-east-1.redshift.amazonaws.com",
            "Port": 5439
        },
        "ClusterCreateTime": "2020-09-13T18:27:58.725Z",
        "AutomatedSnapshotRetentionPeriod": 1,
        "ManualSnapshotRetentionPeriod": -1,
        "ClusterSecurityGroups": [],
        "VpcSecurityGroups": [ 
            {
                "VpcSecurityGroupId": "sg-0bd369e5131079bf3",
                "Status": "active"
            }
        ],
        "ClusterParameterGroups": [
        {
            "ParameterGroupName": "default.redshift-1.0",
            "ParameterApplyStatus": "in-sync",
            "ClusterParameterStatusList": []
        }
        ],
        "ClusterSubnetGroupName": "cluster-subnet-group-1",
        "VpcId": "vpc-0b739af479bea9bff",
        "AvailabilityZone": "us-east-1a",
        "PreferredMaintenanceWindow": "sun:00:00-sun:00:30",
        "PendingModifiedValues": {},
        "ClusterVersion": "1.0",
        "AllowVersionUpgrade": true,
        "NumberOfNodes": 1,
        "PubliclyAccessible": false,
        "Encrypted": true,
        "ClusterPublicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCU0vHJJGfRx4tSl6wVzTM2FEDeE9wyli+9bPuyADordK/tCakDGdkRgTIHzgr53bu3+AS4uwLMKzNrnPzl9iKycUgV29R2lPOQDzaIw4N6SXDqUUyCNQ7OHShjHlZcCtvYn0qC6FRQtVzzRgmbEXJYn1c19hXM/2CGFEcgeL97Bq+M5ut3aVDc+NZW43C9H3KL0GJBGsuJLedQVuZgcsbT+Wey7zbVRYQHe5DhGTkkgoad7P8JMbZo/ZzlK/6hIM1IBJCIAEbvKtCrYP6Z+N4XHBCyVjK7wd5OMZM0SVsz6zarILu3YR8fiBohxlfBF/gigOmL34/f0M3lZaQOgvZ9 Amazon-Redshift\n",
        "ClusterNodes": [
        {
            "NodeRole": "SHARED",
            "PrivateIPAddress": "10.0.0.25",
            "PublicIPAddress": "34.234.29.110"
        }
        ],
        "ClusterRevisionNumber": "18861",
        "Tags": [],
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/f0b4f5a7-a7b5-47b8-b0bf-73203f562886",
        "EnhancedVpcRouting": false,
        "IamRoles": [],
        "PendingActions": [],
        "MaintenanceTrackName": "current",
        "DeferredMaintenanceWindows": [],
        "NextMaintenanceWindowStartTime": "2020-09-20T00:00:00.000Z"
    },
    {
        "ClusterIdentifier": "redshift-cluster-124",    
        "NodeType": "dc2.large",
        "ClusterStatus": "available",
        "ClusterAvailabilityStatus": "Available",
        "MasterUsername": "awsuser",
        "DBName": "dev",
        "Endpoint": {
            "Address": "redshift-cluster-124.cks44thktt7l.us-east-1.redshift.amazonaws.com",
            "Port": 5439
        },
        "ClusterCreateTime": "2020-09-13T18:27:58.725Z",
        "AutomatedSnapshotRetentionPeriod": 1,
        "ManualSnapshotRetentionPeriod": -1,
        "ClusterSecurityGroups": [],
        "VpcSecurityGroups": [ 
            {
                "VpcSecurityGroupId": "sg-0bd369e5131079bf3",
                "Status": "active"
            }
        ],
        "ClusterParameterGroups": [
        {
            "ParameterGroupName": "default.redshift-1.0",
            "ParameterApplyStatus": "in-sync",
            "ClusterParameterStatusList": []
        }
        ],
        "ClusterSubnetGroupName": "cluster-subnet-group-1",
        "VpcId": "vpc-0b739af479bea9bff",
        "AvailabilityZone": "us-east-1a",
        "PreferredMaintenanceWindow": "sun:00:00-sun:00:30",
        "PendingModifiedValues": {},
        "ClusterVersion": "1.0",
        "AllowVersionUpgrade": true,
        "NumberOfNodes": 1,
        "PubliclyAccessible": false,
        "Encrypted": true,
        "ClusterPublicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCU0vHJJGfRx4tSl6wVzTM2FEDeE9wyli+9bPuyADordK/tCakDGdkRgTIHzgr53bu3+AS4uwLMKzNrnPzl9iKycUgV29R2lPOQDzaIw4N6SXDqUUyCNQ7OHShjHlZcCtvYn0qC6FRQtVzzRgmbEXJYn1c19hXM/2CGFEcgeL97Bq+M5ut3aVDc+NZW43C9H3KL0GJBGsuJLedQVuZgcsbT+Wey7zbVRYQHe5DhGTkkgoad7P8JMbZo/ZzlK/6hIM1IBJCIAEbvKtCrYP6Z+N4XHBCyVjK7wd5OMZM0SVsz6zarILu3YR8fiBohxlfBF/gigOmL34/f0M3lZaQOgvZ9 Amazon-Redshift\n",
        "ClusterNodes": [
        {
            "NodeRole": "SHARED",
            "PrivateIPAddress": "10.0.0.25",
            "PublicIPAddress": "34.234.29.110"
        }
        ],
        "ClusterRevisionNumber": "18861",
        "Tags": [],
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/310a3184-b30f-4fc4-a18a-370549c676dc",
        "EnhancedVpcRouting": false,
        "IamRoles": [],
        "PendingActions": [],
        "MaintenanceTrackName": "current",
        "DeferredMaintenanceWindows": [],
        "NextMaintenanceWindowStartTime": "2020-09-20T00:00:00.000Z"
    },
    {
        "ClusterIdentifier": "redshift-cluster-124",    
        "NodeType": "dc2.large",
        "ClusterStatus": "available",
        "ClusterAvailabilityStatus": "Available",
        "MasterUsername": "awsuser",
        "DBName": "dev",
        "Endpoint": {
            "Address": "redshift-cluster-124.cks44thktt7l.us-east-1.redshift.amazonaws.com",
            "Port": 5439
        },
        "ClusterCreateTime": "2020-09-13T18:27:58.725Z",
        "AutomatedSnapshotRetentionPeriod": 1,
        "ManualSnapshotRetentionPeriod": -1,
        "ClusterSecurityGroups": [],
        "VpcSecurityGroups": [ 
            {
                "VpcSecurityGroupId": "sg-0bd369e5131079bf3",
                "Status": "active"
            }
        ],
        "ClusterParameterGroups": [
        {
            "ParameterGroupName": "default.redshift-1.0",
            "ParameterApplyStatus": "in-sync",
            "ClusterParameterStatusList": []
        }
        ],
        "ClusterSubnetGroupName": "cluster-subnet-group-1",
        "VpcId": "vpc-0b739af479bea9bff",
        "AvailabilityZone": "us-east-1a",
        "PreferredMaintenanceWindow": "sun:00:00-sun:00:30",
        "PendingModifiedValues": {},
        "ClusterVersion": "1.0",
        "AllowVersionUpgrade": true,
        "NumberOfNodes": 1,
        "PubliclyAccessible": false,
        "Encrypted": false,
        "ClusterPublicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCU0vHJJGfRx4tSl6wVzTM2FEDeE9wyli+9bPuyADordK/tCakDGdkRgTIHzgr53bu3+AS4uwLMKzNrnPzl9iKycUgV29R2lPOQDzaIw4N6SXDqUUyCNQ7OHShjHlZcCtvYn0qC6FRQtVzzRgmbEXJYn1c19hXM/2CGFEcgeL97Bq+M5ut3aVDc+NZW43C9H3KL0GJBGsuJLedQVuZgcsbT+Wey7zbVRYQHe5DhGTkkgoad7P8JMbZo/ZzlK/6hIM1IBJCIAEbvKtCrYP6Z+N4XHBCyVjK7wd5OMZM0SVsz6zarILu3YR8fiBohxlfBF/gigOmL34/f0M3lZaQOgvZ9 Amazon-Redshift\n",
        "ClusterNodes": [
        {
            "NodeRole": "SHARED",
            "PrivateIPAddress": "10.0.0.25",
            "PublicIPAddress": "34.234.29.110"
        }
        ],
        "ClusterRevisionNumber": "18861",
        "Tags": [],
        "EnhancedVpcRouting": false,
        "IamRoles": [],
        "PendingActions": [],
        "MaintenanceTrackName": "current",
        "DeferredMaintenanceWindows": [],
        "NextMaintenanceWindowStartTime": "2020-09-20T00:00:00.000Z"
    }
];

const listKeys = [
    {
      "KeyId": "143947b8-b22b-4360-9835-af7d346092f9",
      "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/143947b8-b22b-4360-9835-af7d346092f9"
    },
    {
      "KeyId": "1715d6d4-33b2-4722-bb67-33f97781ce47",
      "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/1715d6d4-33b2-4722-bb67-33f97781ce47"
    },
    {
      "KeyId": "2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
      "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/2cff2321-73c6-4bac-95eb-bc9633d3e8a9"
    },
    {
      "KeyId": "310a3184-b30f-4fc4-a18a-370549c676dc",
      "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/310a3184-b30f-4fc4-a18a-370549c676dc"
    },
    {
      "KeyId": "4148a838-df4c-45e7-9850-54682433c8b7",
      "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/4148a838-df4c-45e7-9850-54682433c8b7"
    },
    {
      "KeyId": "7cb78370-cdc6-4ccb-a973-ecc8cbdc0dec",
      "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/7cb78370-cdc6-4ccb-a973-ecc8cbdc0dec"
    },
    {
      "KeyId": "b8789907-b7f7-438d-847e-7d468bac86b2",
      "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/b8789907-b7f7-438d-847e-7d468bac86b2"
    },
    {
      "KeyId": "c48d9687-cdd3-4a1f-9d80-f92a7693c5d0",
      "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/c48d9687-cdd3-4a1f-9d80-f92a7693c5d0"
    },
    {
      "KeyId": "f0b4f5a7-a7b5-47b8-b0bf-73203f562886",
      "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/f0b4f5a7-a7b5-47b8-b0bf-73203f562886"
    }
];

const describeKey = [
    {
        data: {
            KeyMetadata: {
                "AWSAccountId": "112233445566",
                "KeyId": "f0b4f5a7-a7b5-47b8-b0bf-73203f562886",
                "Arn": "arn:aws:kms:us-east-1:112233445566:key/f0b4f5a7-a7b5-47b8-b0bf-73203f562886",
                "CreationDate": "2020-09-13T18:22:03.993Z",
                "Enabled": false,
                "Description": "",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Enabled",
                "DeletionDate": "2020-09-21T00:00:00.000Z",
                "Origin": "AWS_KMS",
                "KeyManager": "CUSTOMER",
                "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            }
        }
    },
    {
        data: {
            KeyMetadata: {
                "AWSAccountId": "112233445566",
                "KeyId": "310a3184-b30f-4fc4-a18a-370549c676dc",
                "Arn": "arn:aws:kms:us-east-1:112233445566:key/310a3184-b30f-4fc4-a18a-370549c676dc",
                "CreationDate": "2020-09-13T18:22:03.993Z",
                "Enabled": false,
                "Description": "",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Enabled",
                "DeletionDate": "2020-09-21T00:00:00.000Z",
                "Origin": "AWS_KMS",
                "KeyManager": "AWS",
                "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            }
        }
    },
];

const createCache = (clusters, listKeys, describeKey) => {
    var keyId = (listKeys && listKeys.length) ? listKeys[0].KeyId : null;
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    data: clusters
                },
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: listKeys
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: describeKey
                }
            }
        }
    };
};

const createdescribeClustersErrorCache = () => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    err: {
                        message: 'error while describing clusters'
                    }
                }
            }
        }
    };
};

const createListKeysErrorCache = (clusters) => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    data: clusters
                },
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    err: {
                        message: 'error while listing KMS keys'
                    }
                }
            }
        }
    };
};

const createDescribeKeyErrorCache = (clusters, listKeys, describeKey) => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    data: clusters
                },
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: listKeys
                }
            },
            describeKey: {
                'us-east-1': {
                    err: {
                        message: 'error while describing key'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': null
            }
        },
        kms: {
            listKeys: {
                'us-east-1': null
            }
        }
    };
};


describe('clusterCmkEncrypted', function () {
    describe('run', function () {
        it('should FAIL if Redshift cluster is not encrypted using KMS customer master key(CMK)', function (done) {
            const cache = createCache([clusters[1]], [listKeys[3]], describeKey[1]);
            clusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if Redshift cluster is encrypted using KMS customer master key(CMK)', function (done) {
            const cache = createCache([clusters[0]], [listKeys[8]], describeKey[0]);
            clusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no redshift clusters found', function (done) {
            const cache = createCache([]);
            clusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Redshift cluster is not encrypted', function (done) {
            const cache = createCache([clusters[2]], listKeys);
            clusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if error while describing redshift clusters', function (done) {
            const cache = createdescribeClustersErrorCache();
            clusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if error while listing KMS keys', function (done) {
            const cache = createListKeysErrorCache(clusters);
            clusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if error while describing KMS key', function (done) {
            const cache = createDescribeKeyErrorCache(clusters, listKeys);
            clusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(3);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if unable to describe redshift clusters', function (done) {
            const cache = createNullCache();
            clusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});