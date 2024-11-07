var expect = require('chai').expect;
var rdsPublicSubnet = require('./rdsPublicSubnet');

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
          "VpcId": "vpc-123",
          "SubnetGroupStatus": "Complete",
          "Subnets": [
            {
              "SubnetIdentifier": "subnet-123",
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
          "VpcId": "vpc-234",
          "SubnetGroupStatus": "Complete",
          "Subnets": [
            {
              "SubnetIdentifier": "subnet-234",
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
];
const describeRouteTables = [
    {
        "Associations": [
          {
            "Main": true,
            "RouteTableAssociationId": "rtbassoc-79c7a000",
            "RouteTableId": "rtb-f6522690",
            "AssociationState": {
              "State": "associated"
            }
          }
        ],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-f6522690",
        "Routes": [
          {
            "DestinationCidrBlock": "172.31.0.0/16",
            "GatewayId": "local",
            "Origin": "CreateRouteTable",
            "State": "active"
          }
        ],
        "Tags": [],
        "VpcId": "vpc-123",
        "OwnerId": "000011112222"
    },
    {
        "Associations": [
          {
            "Main": true,
            "RouteTableAssociationId": "rtbassoc-79c7a000",
            "RouteTableId": "rtb-f6522690",
            "AssociationState": {
              "State": "associated"
            }
          }
        ],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-f6522690",
        "Routes": [
            {
                "DestinationCidrBlock": "172.31.0.0/16",
                "GatewayId": "local",
                "Origin": "CreateRouteTable",
                "State": "active"
            },
            {
                "DestinationCidrBlock": "172.31.0.0/16",
                "GatewayId": "igw-sedwednkq",
                "Origin": "CreateRouteTable",
                "State": "active"
            }
            
        ],
        "Tags": [],
        "VpcId": "vpc-234",
        "OwnerId": "000011112222"
    }
];

const describeSubnets = [
    {
        "AvailabilityZone": "us-east-1c",
        "AvailabilityZoneId": "use1-az4",
        "AvailableIpAddressCount": 4091,
        "CidrBlock": "172.31.16.0/20",
        "DefaultForAz": true,
        "MapPublicIpOnLaunch": true,
        "MapCustomerOwnedIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-123",
        "VpcId": "vpc-123",
        "OwnerId": "000011112222",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-1:000011112222:subnet/subnet-aac6b3e7"
    },
    {
        "AvailabilityZone": "us-east-1c",
        "AvailabilityZoneId": "use1-az4",
        "AvailableIpAddressCount": 4091,
        "CidrBlock": "172.31.16.0/20",
        "DefaultForAz": true,
        "MapPublicIpOnLaunch": true,
        "MapCustomerOwnedIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-234",
        "VpcId": "vpc-234",
        "OwnerId": "000011112222",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-1:000011112222:subnet/subnet-aac6b3e7"
    }
];

const createCache = (dbInstance, subnets, routeTables) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    data: dbInstance
                },
            },
        },
        ec2: {
            describeSubnets: {
                'us-east-1': {
                    data: subnets
                }
            },
            describeRouteTables: {
                'us-east-1': {
                    data: routeTables
                }
            }
        }
    };   
};

const createErrorCache = () => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing db Instance'
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
    };
};

describe('rdsPublicSubnet', function () {
    describe('run', function () {
        it('should PASS if RDS instance has private subnets', function (done) {
            const cache = createCache([describeDBInstances[0]], [describeSubnets[0]], [describeRouteTables[0]]);
            rdsPublicSubnet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('RDS instance is not in a public subnet');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if RDS instance has public subnets', function (done) {
            const cache = createCache([describeDBInstances[1]], [describeSubnets[1]], [describeRouteTables[1]]);
            rdsPublicSubnet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).includes('RDS instance is in a public subnet');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no RDS Instance found', function (done) {
            const cache = createCache([]);
            rdsPublicSubnet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('No RDS instances found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if there unable to query for RDS Innstance', function (done) {
            const cache = createErrorCache();
            rdsPublicSubnet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).includes('Unable to query for RDS instances: ');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return any results describe RDS Instance response not found', function (done) {
            const cache = createNullCache();
            rdsPublicSubnet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});

