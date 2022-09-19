var expect = require('chai').expect;
var rdsRestorable = require('./rdsRestorable');

const describeDBInstances = [
    {
        "DBInstanceIdentifier": "test-db-115",
        "DBInstanceClass": "db.m4.large",
        "Engine": "postgres",
        "DBInstanceStatus": "creating",
        "MasterUsername": "postgres",
        "DBName": "cloudsploit",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "09:07-09:37",
        "LatestRestorableTime": new Date(new Date().setHours(new Date().getHours() - 2)).toISOString(),
        "BackupRetentionPeriod": 7,
        "DBSecurityGroups": [],
        "VpcSecurityGroups": [
          {
            "VpcSecurityGroupId": "sg-aa941691",
            "Status": "active"
          }
        ],
        "DBParameterGroups": [
          {
            "DBParameterGroupName": "default.postgres12",
            "ParameterApplyStatus": "in-sync"
          }
        ],
        "AvailabilityZone": "us-east-1f",
        "DBSubnetGroup": {
          "DBSubnetGroupName": "default-vpc-99de2fe4",
          "DBSubnetGroupDescription": "Created from the RDS Management Console",
          "VpcId": "vpc-99de2fe4",
          "SubnetGroupStatus": "Complete",
          "Subnets": [
            {
              "SubnetIdentifier": "subnet-aac6b3e7",
              "SubnetAvailabilityZone": {
                "Name": "us-east-1c"
              },
              "SubnetOutpost": {},
              "SubnetStatus": "Active"
            }
          ]
        },
        "PreferredMaintenanceWindow": "fri:10:05-fri:10:35",
        "PendingModifiedValues": {
          "MasterUserPassword": "****",
          "ProcessorFeatures": []
        },
        "MultiAZ": false,
        "EngineVersion": "12.3",
        "AutoMinorVersionUpgrade": false,
        "ReadReplicaDBInstanceIdentifiers": [],
        "ReadReplicaDBClusterIdentifiers": [],
        "LicenseModel": "postgresql-license",
        "OptionGroupMemberships": [
          {
            "OptionGroupName": "default:postgres-12",
            "Status": "in-sync"
          }
        ],
        "PubliclyAccessible": false,
        "StatusInfos": [],
        "StorageType": "gp2",
        "DbInstancePort": 0,
        "StorageEncrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:012345678910:key/abcdef10-1517-49d8-b085-77c50b904149",
        "DbiResourceId": "db-ZLVMKFR7AS6SJYTQPXZ4SUH5ZU",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": false,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:test-db-115",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "EnabledCloudwatchLogsExports": [],
        "ProcessorFeatures": [],
        "DeletionProtection": false,
        "AssociatedRoles": []
    },
    {
        "DBInstanceIdentifier": "test-db-115",
        "DBInstanceClass": "db.m4.large",
        "Engine": "postgres",
        "DBInstanceStatus": "creating",
        "MasterUsername": "postgres",
        "DBName": "cloudsploit",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "09:07-09:37",
        "LatestRestorableTime": new Date(new Date().setHours(new Date().getHours() - 7)).toISOString(),
        "BackupRetentionPeriod": 7,
        "DBSecurityGroups": [],
        "VpcSecurityGroups": [
          {
            "VpcSecurityGroupId": "sg-aa941691",
            "Status": "active"
          }
        ],
        "DBParameterGroups": [
          {
            "DBParameterGroupName": "default.postgres12",
            "ParameterApplyStatus": "in-sync"
          }
        ],
        "AvailabilityZone": "us-east-1f",
        "DBSubnetGroup": {
          "DBSubnetGroupName": "default-vpc-99de2fe4",
          "DBSubnetGroupDescription": "Created from the RDS Management Console",
          "VpcId": "vpc-99de2fe4",
          "SubnetGroupStatus": "Complete",
          "Subnets": [
            {
              "SubnetIdentifier": "subnet-aac6b3e7",
              "SubnetAvailabilityZone": {
                "Name": "us-east-1c"
              },
              "SubnetOutpost": {},
              "SubnetStatus": "Active"
            }
          ]
        },
        "PreferredMaintenanceWindow": "fri:10:05-fri:10:35",
        "PendingModifiedValues": {
          "MasterUserPassword": "****",
          "ProcessorFeatures": []
        },
        "MultiAZ": false,
        "EngineVersion": "12.3",
        "AutoMinorVersionUpgrade": false,
        "ReadReplicaDBInstanceIdentifiers": [],
        "ReadReplicaDBClusterIdentifiers": [],
        "LicenseModel": "postgresql-license",
        "OptionGroupMemberships": [
          {
            "OptionGroupName": "default:postgres-12",
            "Status": "in-sync"
          }
        ],
        "PubliclyAccessible": false,
        "StatusInfos": [],
        "StorageType": "gp2",
        "DbInstancePort": 0,
        "StorageEncrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:012345678910:key/abcdef10-1517-49d8-b085-77c50b904149",
        "DbiResourceId": "db-ZLVMKFR7AS6SJYTQPXZ4SUH5ZU",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": false,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:test-db-115",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "EnabledCloudwatchLogsExports": [],
        "ProcessorFeatures": [],
        "DeletionProtection": false,
        "AssociatedRoles": []
    },
    {
        "DBInstanceIdentifier": "test-db-115",
        "DBInstanceClass": "db.m4.large",
        "Engine": "postgres",
        "DBInstanceStatus": "creating",
        "MasterUsername": "postgres",
        "DBName": "cloudsploit",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "09:07-09:37",
        "LatestRestorableTime": new Date(new Date().setHours(new Date().getHours() - 25)).toISOString(),
        "BackupRetentionPeriod": 2,
        "DBSecurityGroups": [],
        "VpcSecurityGroups": [
          {
            "VpcSecurityGroupId": "sg-aa941691",
            "Status": "active"
          }
        ],
        "DBParameterGroups": [
          {
            "DBParameterGroupName": "default.postgres12",
            "ParameterApplyStatus": "in-sync"
          }
        ],
        "AvailabilityZone": "us-east-1f",
        "DBSubnetGroup": {
          "DBSubnetGroupName": "default-vpc-99de2fe4",
          "DBSubnetGroupDescription": "Created from the RDS Management Console",
          "VpcId": "vpc-99de2fe4",
          "SubnetGroupStatus": "Complete",
          "Subnets": [
            {
              "SubnetIdentifier": "subnet-aac6b3e7",
              "SubnetAvailabilityZone": {
                "Name": "us-east-1c"
              },
              "SubnetOutpost": {},
              "SubnetStatus": "Active"
            }
          ]
        },
        "PreferredMaintenanceWindow": "fri:10:05-fri:10:35",
        "PendingModifiedValues": {
          "MasterUserPassword": "****",
          "ProcessorFeatures": []
        },
        "MultiAZ": false,
        "EngineVersion": "12.3",
        "AutoMinorVersionUpgrade": false,
        "ReadReplicaDBInstanceIdentifiers": [],
        "ReadReplicaDBClusterIdentifiers": [],
        "LicenseModel": "postgresql-license",
        "OptionGroupMemberships": [
          {
            "OptionGroupName": "default:postgres-12",
            "Status": "in-sync"
          }
        ],
        "PubliclyAccessible": true,
        "StatusInfos": [],
        "StorageType": "gp2",
        "DbInstancePort": 0,
        "StorageEncrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:012345678910:key/88888828-1517-49d8-b085-77c50b904149",
        "DbiResourceId": "db-ZLVMKFR7AS6SJYTQPXZ4SUH5ZU",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": false,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:test-db-115",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "EnabledCloudwatchLogsExports": [],
        "ProcessorFeatures": [],
        "DeletionProtection": false,
        "AssociatedRoles": []
    },
    {
        "DBInstanceIdentifier": "test-db-115",
        "DBInstanceClass": "db.m4.large",
        "Engine": "postgres",
        "DBInstanceStatus": "creating",
        "MasterUsername": "postgres",
        "DBName": "cloudsploit",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "09:07-09:37",
        "BackupRetentionPeriod": 2,
        "AvailabilityZone": "us-east-1f",
        "EngineVersion": "12.3",
        "PubliclyAccessible": true,
        "PerformanceInsightsEnabled": false,
        "EnabledCloudwatchLogsExports": []
    },
    {
        "DBInstanceIdentifier": "test-db-115",
        "DBInstanceClass": "db.m4.large",
        "Engine": "docdb",
        "DBInstanceStatus": "creating",
        "MasterUsername": "docdb",
        "DBName": "cloudsploit",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "09:07-09:37",
        "BackupRetentionPeriod": 2,
        "AvailabilityZone": "us-east-1f",
        "EngineVersion": "12.3",
        "PubliclyAccessible": true,
        "PerformanceInsightsEnabled": false,
        "EnabledCloudwatchLogsExports": []
    },
    {
        "DBInstanceIdentifier": "test-db-115",
        "DBInstanceClass": "db.m4.large",
        "Engine": "aurora-mysql",
        "DBInstanceStatus": "creating",
        "MasterUsername": "aurora-mysql",
        "DBName": "cloudsploit",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "09:07-09:37",
        "BackupRetentionPeriod": 2,
        "AvailabilityZone": "us-east-1f",
        "EngineVersion": "5.7.mysql_aurora.2.07.2",
        "PubliclyAccessible": true,
        "PerformanceInsightsEnabled": false,
        "EnabledCloudwatchLogsExports": []
    }
];

const describeDBClusters = [
    {
        "AllocatedStorage": 1,
        "AvailabilityZones": [
            "us-east-1a",
            "us-east-1f",
            "us-east-1c"
        ],
        "BackupRetentionPeriod": 1,
        "DBClusterIdentifier": "database-2",
        "DBClusterParameterGroup": "default.neptune1",
        "DBSubnetGroup": "default-vpc-0f4f4575a74fac014",
        "Status": "available",
        "EarliestRestorableTime": "2021-11-16T09:01:51.536000+00:00",
        "Endpoint": "database-2.cluster-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "ReaderEndpoint": "database-2.cluster-ro-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "MultiAZ": false,
        "Engine": "neptune",
        "EngineVersion": "1.0.5.1",
        "LatestRestorableTime": new Date(new Date().setHours(new Date().getHours() - 2)).toISOString(),
        "Port": 8182,
        "MasterUsername": "admin",
        "PreferredBackupWindow": "03:20-03:50",
        "PreferredMaintenanceWindow": "fri:09:21-fri:09:51",
        "ReadReplicaIdentifiers": [],
        "DBClusterMembers": [
            {
                "DBInstanceIdentifier": "database-2-instance-1",
                "IsClusterWriter": true,
                "DBClusterParameterGroupStatus": "in-sync",
                "PromotionTier": 1
            }
        ],
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-0cb6c99daaa6b73c5",
                "Status": "active"
            }
        ],
        "HostedZoneId": "ZUFXD4SLT2LS7",
        "StorageEncrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "DbClusterResourceId": "cluster-WNY2ZTZWH4RQ2CTKEEP4GVCPU4",
        "DBClusterArn": "arn:aws:rds:us-east-1:000111222333:cluster:database-2",
        "AssociatedRoles": [],
    },
    {
        "AllocatedStorage": 1,
        "AvailabilityZones": [
            "us-east-1a",
            "us-east-1f",
            "us-east-1c"
        ],
        "BackupRetentionPeriod": 1,
        "DBClusterIdentifier": "database-2",
        "DBClusterParameterGroup": "default.neptune1",
        "DBSubnetGroup": "default-vpc-0f4f4575a74fac014",
        "Status": "available",
        "EarliestRestorableTime": "2021-11-16T09:01:51.536000+00:00",
        "Endpoint": "database-2.cluster-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "ReaderEndpoint": "database-2.cluster-ro-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "MultiAZ": false,
        "Engine": "neptune",
        "EngineVersion": "1.0.5.1",
        "LatestRestorableTime": new Date(new Date().setHours(new Date().getHours() - 7)).toISOString(),
        "Port": 8182,
        "MasterUsername": "admin",
        "PreferredBackupWindow": "03:20-03:50",
        "PreferredMaintenanceWindow": "fri:09:21-fri:09:51",
        "DBClusterMembers": [
            {
                "DBInstanceIdentifier": "database-2-instance-1",
                "IsClusterWriter": true,
                "DBClusterParameterGroupStatus": "in-sync",
                "PromotionTier": 1
            }
        ],
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-0cb6c99daaa6b73c5",
                "Status": "active"
            }
        ],
        "HostedZoneId": "ZUFXD4SLT2LS7",
        "StorageEncrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "DbClusterResourceId": "cluster-WNY2ZTZWH4RQ2CTKEEP4GVCPU4",
        "DBClusterArn": "arn:aws:rds:us-east-1:000111222333:cluster:database-2",
    },
    {
        "AllocatedStorage": 1,
        "AvailabilityZones": [
            "us-east-1a",
            "us-east-1f",
            "us-east-1c"
        ],
        "BackupRetentionPeriod": 1,
        "DBClusterIdentifier": "database-2",
        "DBClusterParameterGroup": "default.neptune1",
        "DBSubnetGroup": "default-vpc-0f4f4575a74fac014",
        "Status": "available",
        "EarliestRestorableTime": "2021-11-16T09:01:51.536000+00:00",
        "Endpoint": "database-2.cluster-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "ReaderEndpoint": "database-2.cluster-ro-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "MultiAZ": false,
        "Engine": "neptune",
        "EngineVersion": "1.0.5.1",
        "LatestRestorableTime": new Date(new Date().setHours(new Date().getHours() - 25)).toISOString(),
        "Port": 8182,
        "MasterUsername": "admin",
        "PreferredBackupWindow": "03:20-03:50",
        "PreferredMaintenanceWindow": "fri:09:21-fri:09:51",
        "DBClusterMembers": [
            {
                "DBInstanceIdentifier": "database-2-instance-1",
                "IsClusterWriter": true,
                "DBClusterParameterGroupStatus": "in-sync",
                "PromotionTier": 1
            }
        ],
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-0cb6c99daaa6b73c5",
                "Status": "active"
            }
        ],
        "HostedZoneId": "ZUFXD4SLT2LS7",
        "StorageEncrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "DbClusterResourceId": "cluster-WNY2ZTZWH4RQ2CTKEEP4GVCPU4",
        "DBClusterArn": "arn:aws:rds:us-east-1:000111222333:cluster:database-2",
    },
    {
        "AllocatedStorage": 1,
        "AvailabilityZones": [
            "us-east-1a",
            "us-east-1f",
            "us-east-1c"
        ],
        "BackupRetentionPeriod": 1,
        "DBClusterIdentifier": "database-2",
        "DBClusterParameterGroup": "default.neptune1",
        "DBSubnetGroup": "default-vpc-0f4f4575a74fac014",
        "Status": "available",
        "EarliestRestorableTime": "2021-11-16T09:01:51.536000+00:00",
        "Endpoint": "database-2.cluster-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "ReaderEndpoint": "database-2.cluster-ro-cscif9l5pu36.us-east-1.neptune.amazonaws.com",
        "MultiAZ": false,
        "Engine": "neptune",
        "EngineVersion": "1.0.5.1",
        "Port": 8182,
        "MasterUsername": "admin",
        "PreferredBackupWindow": "03:20-03:50",
        "PreferredMaintenanceWindow": "fri:09:21-fri:09:51",
        "DBClusterMembers": [
            {
                "DBInstanceIdentifier": "database-2-instance-1",
                "IsClusterWriter": true,
                "DBClusterParameterGroupStatus": "in-sync",
                "PromotionTier": 1
            }
        ],
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-0cb6c99daaa6b73c5",
                "Status": "active"
            }
        ],
        "HostedZoneId": "ZUFXD4SLT2LS7",
        "StorageEncrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "DbClusterResourceId": "cluster-WNY2ZTZWH4RQ2CTKEEP4GVCPU4",
        "DBClusterArn": "arn:aws:rds:us-east-1:000111222333:cluster:database-2",
    },
];

const createCache = (rdsInstances, dBClusters) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: null,
                    data: rdsInstances
                },
            },
            describeDBClusters: {
                'us-east-1': {
                    err: null,
                    data: dBClusters
                },
            },
        }
    };
};

const createErrorCache = () => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: {
                        message: 'error while describing RDS instances'
                    },
                },
            },
            describeDBClusters: {
                'us-east-1': {
                    err: {
                        message: 'error while describing RDS instances'
                    },
                },
            },
        }
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': null,
            },
            describeDBClusters: {
                'us-east-1': null,
            }
        }
    };
};

describe('rdsRestorable', function () {
    describe('run', function () {
        it('should PASS if no RDS instance is found', function (done) {
            const cache = createCache([]);
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('No RDS instances found');
                done();
            });
        });

        it('should PASS if RDS instance\'s restorable time is less than 6 hours', function (done) {
            const cache = createCache([describeDBInstances[0]]);
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('RDS instance restorable time is');
                done();
            });
        });

        it('should PASS with warning if RDS instance have a restorable time of greater than 6 hours but less then 24 hours', function (done) {
            const cache = createCache([describeDBInstances[1]]);
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).includes('RDS instance restorable time is');
                done();
            });
        });

        it('should PASS if the db instance is of type docDB', function (done) {
            const cache = createCache([describeDBInstances[4]]);
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('DocumentDB engine uses incremental backups');
                done();
            });
        });

        it('should PASS if RDS cluster\'s restorable time is less than 6 hours', function (done) {
            const cache = createCache([describeDBInstances[5]], [describeDBClusters[0]]);
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('RDS cluster restorable time is');
                done();
            });
        });

        it('should PASS with warning if RDS cluster have a restorable time of greater than 6 hours but less then 24 hours', function (done) {
            const cache = createCache([describeDBInstances[5]], [describeDBClusters[1]]);
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).includes('RDS cluster restorable time is');
                done();
            });
        });

        it('should FAIL if RDS instance have a restorable time of greater than 24 hours', function (done) {
            const cache = createCache([describeDBInstances[2]]);
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).includes('RDS instance restorable time is');
                done();
            });
        });

        it('should FAIL if RDS instance does not have a restorable time', function (done) {
            const cache = createCache([describeDBInstances[3]]);
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).includes('RDS instance does not have a restorable time');
                done();
            });
        });

        it('should FAIL if RDS db cluster have a restorable time of greater than 24 hours', function (done) {
            const cache = createCache([describeDBInstances[5]], [describeDBClusters[2]]);
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).includes('RDS cluster restorable time is');
                done();
            });
        });

        it('should FAIL if RDS db cluster does not have a restorable time', function (done) {
            const cache = createCache([describeDBInstances[5]], [describeDBClusters[3]]);
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).includes('RDS cluster does not have a restorable time');
                done();
            });
        });

        it('should UNKNOWN if error while describing RDS instances/clusters', function (done) {
            const cache = createErrorCache();
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if unable to describe RDS instances/clusters', function (done) {
            const cache = createNullCache();
            rdsRestorable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
