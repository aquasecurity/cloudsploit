var expect = require('chai').expect;
var rdsCmkEncryptionEnabled = require('./rdsCmkEncryptionEnabled');

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
        "BackupRetentionPeriod": 0,
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
        "BackupRetentionPeriod": 0,
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
        "BackupRetentionPeriod": 0,
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
        "StorageEncrypted": false,
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
    }
];

const listAliases = [
    {
        "AliasArn": "arn:aws:kms:us-east-1:012345678910:alias/example1", 
        "AliasName": "custom/key", 
        "TargetKeyId": "abcdef10-1517-49d8-b085-77c50b904149"
    },
    {
        "AliasArn": "arn:aws:kms:us-east-1:012345678910:alias/customRdsKey", 
        "AliasName": "alias/aws/rds", 
        "TargetKeyId": "abcdef10-1517-49d8-b085-77c50b904149"
    }
];

const createCache = (rdsInstances, kmsAliases) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: null,
                    data: rdsInstances
                },
            },
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    err: null,
                    data: kmsAliases
                },
            },
        },
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
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    err: {
                        message: 'error while listing KMS aliases'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': null,
            },
        },
        kms: {
            listAliases: {
                'us-east-1': null,
            },
        },
    };
};

describe('rdsCmkEncryptionEnabled', function () {
    describe('run', function () {
        it('should PASS if RDS DB instance is using Customer Master Key for encryption', function (done) {
            const cache = createCache([describeDBInstances[0]], [listAliases[0]]);
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if RDS DB instance is not using Customer Master Key for encryption', function (done) {
            const cache = createCache([describeDBInstances[0]], [listAliases[1]]);
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
                
        it('should FAIL if RDS DB instance encryption key is not found', function (done) {
            const cache = createCache([describeDBInstances[1]], [listAliases[1]]);
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
                
        it('should FAIL if RDS DB instance does not have encryption enabled', function (done) {
            const cache = createCache([describeDBInstances[2]], [listAliases[1]]);
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if error while describing RDS DB instances', function (done) {
            const cache = createErrorCache();
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if unable to describe RDS DB instances', function (done) {
            const cache = createNullCache();
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});