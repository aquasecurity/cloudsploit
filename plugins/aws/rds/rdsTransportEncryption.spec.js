var expect = require('chai').expect;
var rdsTransportEncryption = require('./rdsTransportEncryption.js');

const describeDBInstances = [
    {
        "DBInstanceIdentifier": "database-2",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "sqlserver-ex",
        "DBInstanceStatus": "available",
        "MasterUsername": "admin",
        "Endpoint": {
            "Address": "database-2.csumzsa0neyf.us-east-1.rds.amazonaws.com",
            "Port": 1433,
            "HostedZoneId": "Z2R2ITUGPM61AM"
        },
        "AllocatedStorage": 20,
        "InstanceCreateTime": "2020-09-19T22:40:13.061Z",
        "PreferredBackupWindow": "07:14-07:44",
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
                "DBParameterGroupName": "default.sqlserver-ex-14.0",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "AvailabilityZone": "us-east-1b",
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
                },
                {
                    "SubnetIdentifier": "subnet-673a9a46",
                    "SubnetAvailabilityZone": {
                        "Name": "us-east-1b"
                    },
                    "SubnetOutpost": {},
                    "SubnetStatus": "Active"
                },
                {
                    "SubnetIdentifier": "subnet-06aa0f60",
                    "SubnetAvailabilityZone": {
                        "Name": "us-east-1a"
                    },
                    "SubnetOutpost": {},
                    "SubnetStatus": "Active"
                },
                {
                    "SubnetIdentifier": "subnet-e83690b7",
                    "SubnetAvailabilityZone": {
                        "Name": "us-east-1d"
                    },
                    "SubnetOutpost": {},
                    "SubnetStatus": "Active"
                },
                {
                    "SubnetIdentifier": "subnet-c21b84cc",
                    "SubnetAvailabilityZone": {
                        "Name": "us-east-1f"
                    },
                    "SubnetOutpost": {},
                    "SubnetStatus": "Active"
                },
                {
                    "SubnetIdentifier": "subnet-6a8b635b",
                    "SubnetAvailabilityZone": {
                        "Name": "us-east-1e"
                    },
                    "SubnetOutpost": {},
                    "SubnetStatus": "Active"
                }
            ]
        },
        "PreferredMaintenanceWindow": "thu:09:56-thu:10:26",
        "PendingModifiedValues": {},
        "MultiAZ": false,
        "EngineVersion": "14.00.3281.6.v1",
        "AutoMinorVersionUpgrade": false,
        "ReadReplicaDBInstanceIdentifiers": [],
        "LicenseModel": "license-included",
        "OptionGroupMemberships": [
            {
                "OptionGroupName": "default:sqlserver-ex-14-00",
                "Status": "in-sync"
            }
        ],
        "CharacterSetName": "SQL_Latin1_General_CP1_CI_AS",
        "PubliclyAccessible": false,
        "StorageType": "gp2",
        "DbInstancePort": 0,
        "StorageEncrypted": false,
        "DbiResourceId": "db-IMU3ZRYUO4IYJFZDPQTQZB3ISQ",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": true,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:database-2",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "DeletionProtection": false,
        "AssociatedRoles": []
    },
    {
        "DBInstanceIdentifier": "database-2",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "postgres",
        "DBInstanceStatus": "available",
        "MasterUsername": "admin",
        "Endpoint": {
            "Address": "database-2.csumzsa0neyf.us-east-1.rds.amazonaws.com",
            "Port": 1433,
            "HostedZoneId": "Z2R2ITUGPM61AM"
        },
        "AllocatedStorage": 20,
        "InstanceCreateTime": "2020-09-19T22:40:13.061Z",
        "PreferredBackupWindow": "07:14-07:44",
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
                "DBParameterGroupName": "default.sqlserver-ex-14.0",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "AvailabilityZone": "us-east-1b",
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
                },
                {
                    "SubnetIdentifier": "subnet-673a9a46",
                    "SubnetAvailabilityZone": {
                        "Name": "us-east-1b"
                    },
                    "SubnetOutpost": {},
                    "SubnetStatus": "Active"
                },
                {
                    "SubnetIdentifier": "subnet-06aa0f60",
                    "SubnetAvailabilityZone": {
                        "Name": "us-east-1a"
                    },
                    "SubnetOutpost": {},
                    "SubnetStatus": "Active"
                },
                {
                    "SubnetIdentifier": "subnet-e83690b7",
                    "SubnetAvailabilityZone": {
                        "Name": "us-east-1d"
                    },
                    "SubnetOutpost": {},
                    "SubnetStatus": "Active"
                },
                {
                    "SubnetIdentifier": "subnet-c21b84cc",
                    "SubnetAvailabilityZone": {
                        "Name": "us-east-1f"
                    },
                    "SubnetOutpost": {},
                    "SubnetStatus": "Active"
                },
                {
                    "SubnetIdentifier": "subnet-6a8b635b",
                    "SubnetAvailabilityZone": {
                        "Name": "us-east-1e"
                    },
                    "SubnetOutpost": {},
                    "SubnetStatus": "Active"
                }
            ]
        },
        "PreferredMaintenanceWindow": "thu:09:56-thu:10:26",
        "PendingModifiedValues": {},
        "MultiAZ": false,
        "EngineVersion": "14.00.3281.6.v1",
        "AutoMinorVersionUpgrade": false,
        "ReadReplicaDBInstanceIdentifiers": [],
        "LicenseModel": "license-included",
        "OptionGroupMemberships": [
            {
                "OptionGroupName": "default:sqlserver-ex-14-00",
                "Status": "in-sync"
            }
        ],
        "CharacterSetName": "SQL_Latin1_General_CP1_CI_AS",
        "PubliclyAccessible": false,
        "StorageType": "gp2",
        "DbInstancePort": 0,
        "StorageEncrypted": false,
        "DbiResourceId": "db-IMU3ZRYUO4IYJFZDPQTQZB3ISQ",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": true,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:database-2",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "DeletionProtection": false,
        "AssociatedRoles": []
    }
];

const describeDBParameters = [
    {
        "ParameterName": "rds.force_ssl",
        "ParameterValue": "0",
        "Description": "Force SSL connections.",
        "Source": "system",
        "ApplyType": "static",
        "DataType": "boolean",
        "AllowedValues": "0,1",
        "IsModifiable": true,
        "MinimumEngineVersion": "14.00.1000.169.v1",
        "ApplyMethod": "pending-reboot"
    },
    {
        "ParameterName": "rds.force_ssl",
        "ParameterValue": "1",
        "Description": "Force SSL connections.",
        "Source": "system",
        "ApplyType": "static",
        "DataType": "boolean",
        "AllowedValues": "0,1",
        "IsModifiable": true,
        "MinimumEngineVersion": "14.00.1000.169.v1",
        "ApplyMethod": "pending-reboot"
    }
]

const createCache = (dbInstances, dbParameters) => {
    var dbParameterGroupName = (dbInstances[0] && dbInstances[0].DBParameterGroups[0] && dbInstances[0].DBParameterGroups[0].DBParameterGroupName) ? dbInstances[0].DBParameterGroups[0].DBParameterGroupName : null;
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: null,
                    data: dbInstances
                },
            },
            describeDBParameters: {
                'us-east-1': {
                    [dbParameterGroupName]: {
                        data: {
                            Parameters: dbParameters
                        }
                    }
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
                        message: 'error describing parameter groups'
                    },
                },
            },
            describeDBParameters: {
                'us-east-1': {
                    err: {
                        message: 'error describing parameter groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBParameterGroups: {
                'us-east-1': null,
            },
            describeDBParameters: {
                'us-east-1': null,
            },
        },
    };
};

describe('rdsTransportEncryption', function () {
    describe('run', function () {
        it('should PASS if RDS DB instance has transport encryption enabled', function (done) {
            const cache = createCache([describeDBInstances[0]], [describeDBParameters[0]]);
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if RDS DB instance does not have transport encryption enabled', function (done) {
            const cache = createCache([describeDBInstances[0]], [describeDBParameters[1]]);
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no RDS DB instance found', function (done) {
            const cache = createCache([]);
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if no RDS DB parameters found', function (done) {
            const cache = createCache([describeDBInstances[0]], []);
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if error while describing RDS DB instances', function (done) {
            const cache = createErrorCache();
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if unable to query for RDS DB instances', function (done) {
            const cache = createNullCache();
            rdsTransportEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
      