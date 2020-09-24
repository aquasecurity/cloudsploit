const expect = require('chai').expect;
const redshiftClusterCmkEncrypted = require('./redshiftClusterCmkEncrypted');

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
    },
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
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445565:key/f0b4f5a7-a7b5-47b8-b0bf-73203f562886",
        "EnhancedVpcRouting": false,
        "IamRoles": [],
        "PendingActions": [],
        "MaintenanceTrackName": "current",
        "DeferredMaintenanceWindows": [],
        "NextMaintenanceWindowStartTime": "2020-09-20T00:00:00.000Z"
    }
];

const listAliases = [
    {
      AliasName: 'alias/aws/rds',
      AliasArn: 'arn:aws:kms:us-east-1:112233445566:alias/aws/rds',
      TargetKeyId: '2cff2321-73c6-4bac-95eb-bc9633d3e8a9'
    },
    {
      AliasName: 'alias/aws/redshift',
      AliasArn: 'arn:aws:kms:us-east-1:112233445566:alias/aws/redshift',
      TargetKeyId: '310a3184-b30f-4fc4-a18a-370549c676dc'
    },
];

const createCache = (clusters, listAliases) => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    data: clusters
                },
            }
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    data: listAliases
                }
            },
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

const createListAliasesErrorCache = (clusters) => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    data: clusters
                },
            }
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    err: {
                        message: 'error while listing KMS aliases'
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
            listAliases: {
                'us-east-1': null
            }
        }
    };
};


describe('redshiftClusterCmkEncrypted', function () {
    describe('run', function () {
        it('should FAIL if Redshift cluster is not encrypted using KMS customer master key(CMK)', function (done) {
            const cache = createCache([clusters[0]], [listAliases[0]]);
            redshiftClusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if Redshift cluster is encrypted using KMS customer master key(CMK)', function (done) {
            const cache = createCache([clusters[1]], [listAliases[1]]);
            redshiftClusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no redshift clusters found', function (done) {
            const cache = createCache([]);
            redshiftClusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Redshift cluster is not encrypted', function (done) {
            const cache = createCache([clusters[2]], listAliases);
            redshiftClusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Redshift cluster encyption key not found', function (done) {
            const cache = createCache([clusters[3]], listAliases);
            redshiftClusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        it('should UNKNOWN if error while describing redshift clusters', function (done) {
            const cache = createdescribeClustersErrorCache();
            redshiftClusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if error while listing KMS aliases', function (done) {
            const cache = createListAliasesErrorCache(clusters);
            redshiftClusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if unable to describe redshift clusters', function (done) {
            const cache = createNullCache();
            redshiftClusterCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});