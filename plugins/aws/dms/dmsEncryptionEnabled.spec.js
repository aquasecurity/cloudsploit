var expect = require('chai').expect;
var dmsEncryptionEnabled = require('./dmsEncryptionEnabled');

const createCache = (rErr, rData, lData, lErr, dData, dErr, aData, aErr) => {
    return {
        dms: {
            describeReplicationInstances: {
                'us-east-1': {
                    data: rData,
                    err: rErr
                }
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: lData,
                    err: lErr
                }
            },
            describeKey: {
                'us-east-1': dData
            },
            listAliases: {
                'us-east-1': {
                    data: aData,
                    err: aErr
                }
            }
        }
    };
};

describe('dmsEncryptionEnabled', function () {
    describe('run', function () {
        it('should UNKNOWN if replication instance has no data', function (done) {
            const cache = createCache();
            dmsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for replication instances')
                done();
            });
        });

        it('should PASS if replication instance matches the regex pattern', function (done) {

            const cache = createCache(null, [
                {
                    "ReplicationInstanceIdentifier": "gio-test-2",
                    "ReplicationInstanceClass": "dms.t2.micro",
                    "ReplicationInstanceStatus": "available",
                    "AllocatedStorage": 5,
                    "InstanceCreateTime": "2020-04-02T16:29:34.991Z",
                    "VpcSecurityGroups": [
                        {
                            "VpcSecurityGroupId": "sg-588f0513",
                            "Status": "active"
                        }
                    ],
                    "AvailabilityZone": "us-east-1a",
                    "ReplicationSubnetGroup": {
                        "ReplicationSubnetGroupIdentifier": "default-vpc-8a7c9cf0",
                        "ReplicationSubnetGroupDescription": "default group created by console for vpc id vpc-8a7c9cf0",
                        "VpcId": "vpc-8a7c9cf0",
                        "SubnetGroupStatus": "Complete",
                        "Subnets": [
                            {
                                "SubnetIdentifier": "subnet-00d54b39d82c253bf",
                                "SubnetAvailabilityZone": {
                                    "Name": "us-east-1a"
                                },
                                "SubnetStatus": "Active"
                            },
                            {
                                "SubnetIdentifier": "subnet-00a354f3b627de72f",
                                "SubnetAvailabilityZone": {
                                    "Name": "us-east-1a"
                                },
                                "SubnetStatus": "Active"
                            },
                            {
                                "SubnetIdentifier": "subnet-0b03279f0fe7e554f",
                                "SubnetAvailabilityZone": {
                                    "Name": "us-east-1c"
                                },
                                "SubnetStatus": "Active"
                            },
                            {
                                "SubnetIdentifier": "subnet-07f02957e441bde95",
                                "SubnetAvailabilityZone": {
                                    "Name": "us-east-1c"
                                },
                                "SubnetStatus": "Active"
                            },
                            {
                                "SubnetIdentifier": "subnet-09a19d1207721a25a",
                                "SubnetAvailabilityZone": {
                                    "Name": "us-east-1b"
                                },
                                "SubnetStatus": "Active"
                            },
                            {
                                "SubnetIdentifier": "subnet-0774053c76031299e",
                                "SubnetAvailabilityZone": {
                                    "Name": "us-east-1a"
                                },
                                "SubnetStatus": "Active"
                            },
                            {
                                "SubnetIdentifier": "subnet-0b1019992ba7fed70",
                                "SubnetAvailabilityZone": {
                                    "Name": "us-east-1b"
                                },
                                "SubnetStatus": "Active"
                            },
                            {
                                "SubnetIdentifier": "subnet-0a73fa2127885acb6",
                                "SubnetAvailabilityZone": {
                                    "Name": "us-east-1c"
                                },
                                "SubnetStatus": "Active"
                            },
                            {
                                "SubnetIdentifier": "subnet-08ce5ab7e15eb502c",
                                "SubnetAvailabilityZone": {
                                    "Name": "us-east-1b"
                                },
                                "SubnetStatus": "Active"
                            }
                        ]
                    },
                    "PreferredMaintenanceWindow": "fri:06:34-fri:07:04",
                    "PendingModifiedValues": {},
                    "MultiAZ": false,
                    "EngineVersion": "3.3.1",
                    "AutoMinorVersionUpgrade": true,
                    "KmsKeyId": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b",
                    "ReplicationInstanceArn": "arn:aws:dms:us-east-1:1156999144843:rep:IP5IC7QARKU4GWDJDPQMGHKG5I",
                    "ReplicationInstancePrivateIpAddress": "172.31.0.71",
                    "ReplicationInstancePublicIpAddresses": [
                        null
                    ],
                    "ReplicationInstancePrivateIpAddresses": [
                        "172.31.0.71"
                    ],
                    "PubliclyAccessible": false
                }], [
                {
                    "KeyId": "b4022674-ba90-4abc-9087-543cad09879b",
                    "KeyArn": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b"
                }
            ], null, {
                "b4022674-ba90-4abc-9087-543cad09879b": {
                    "data": {
                        "KeyMetadata": {
                            "AWSAccountId": "1156999144843",
                            "KeyId": "b4022674-ba90-4abc-9087-543cad09879b",
                            "Arn": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b",
                            "CreationDate": "2020-03-25T14:05:09.299Z",
                            "Enabled": true,
                            "Description": "Used for S3 encryption",
                            "KeyUsage": "ENCRYPT_DECRYPT",
                            "KeyState": "Enabled",
                            "Origin": "AWS_KMS",
                            "KeyManager": "CUSTOMER",
                            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
                            "EncryptionAlgorithms": [
                                "SYMMETRIC_DEFAULT"
                            ]
                        }
                    }
                }
            }, null, [
                {
                    "AliasName": "alias/S3",
                    "AliasArn": "arn:aws:kms:us-east-1:1156999144843:alias/S3",
                    "TargetKeyId": "b4022674-ba90-4abc-9087-543cad09879b"
                }
            ], null);
            dmsEncryptionEnabled.run(cache, {dms_encryption_allow_pattern: '^gio-test-2$'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is whitelisted via custom setting')
                done();
            });
        });

        it('should FAIL if replication instance has encryption but matching alias could not be found ', function (done) {
            const cache = createCache(null, [
                {
                "ReplicationInstanceIdentifier": "gio-test-2",
                "ReplicationInstanceClass": "dms.t2.micro",
                "ReplicationInstanceStatus": "available",
                "AllocatedStorage": 5,
                "InstanceCreateTime": "2020-04-02T16:29:34.991Z",
                "VpcSecurityGroups": [
                    {
                        "VpcSecurityGroupId": "sg-588f0513",
                        "Status": "active"
                    }
                ],
                "AvailabilityZone": "us-east-1a",
                "ReplicationSubnetGroup": {
                    "ReplicationSubnetGroupIdentifier": "default-vpc-8a7c9cf0",
                    "ReplicationSubnetGroupDescription": "default group created by console for vpc id vpc-8a7c9cf0",
                    "VpcId": "vpc-8a7c9cf0",
                    "SubnetGroupStatus": "Complete",
                    "Subnets": [
                        {
                            "SubnetIdentifier": "subnet-00d54b39d82c253bf",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-00a354f3b627de72f",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0b03279f0fe7e554f",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-07f02957e441bde95",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-09a19d1207721a25a",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0774053c76031299e",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0b1019992ba7fed70",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0a73fa2127885acb6",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-08ce5ab7e15eb502c",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        }
                    ]
                },
                "PreferredMaintenanceWindow": "fri:06:34-fri:07:04",
                "PendingModifiedValues": {},
                "MultiAZ": false,
                "EngineVersion": "3.3.1",
                "AutoMinorVersionUpgrade": true,
                "KmsKeyId": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b",
                "ReplicationInstanceArn": "arn:aws:dms:us-east-1:1156999144843:rep:IP5IC7QARKU4GWDJDPQMGHKG5I",
                "ReplicationInstancePrivateIpAddress": "172.31.0.71",
                "ReplicationInstancePublicIpAddresses": [
                    null
                ],
                "ReplicationInstancePrivateIpAddresses": [
                    "172.31.0.71"
                ],
                "PubliclyAccessible": false
            }], [{
                "KeyId": "b4022674-ba90-4abc-9087-543cad09879b",
                "KeyArn": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b"
            }], null, {"b4022674-ba90-4abc-9087-543cad09879b": {
                    "data": {
                        "KeyMetadata": {
                            "AWSAccountId": "1156999144843",
                            "KeyId": "b4022674-ba90-4abc-9087-543cad09879b",
                            "Arn": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b",
                            "CreationDate": "2020-03-25T14:05:09.299Z",
                            "Enabled": true,
                            "Description": "Used for S3 encryption",
                            "KeyUsage": "ENCRYPT_DECRYPT",
                            "KeyState": "Enabled",
                            "Origin": "AWS_KMS",
                            "KeyManager": "CUSTOMER",
                            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
                            "EncryptionAlgorithms": [
                                "SYMMETRIC_DEFAULT"
                            ]
                        }
                    }
                }}, null, [{
                "AliasName": "alias/my-alias",
                "AliasArn": "arn:aws:kms:us-east-1:1156999144843:alias/my-alias",
                "TargetKeyId": "b4022674-ba90-4abc-9087-543cad09879b"
            }], null);
            dmsEncryptionEnabled.run(cache, {dms_encryption_kms_alias: 'alias/my-other-alias'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has encryption enabled but matching KMS key alias')
                done();
            });
        });

        it('should PASS if replication instance has encryption with matching alias', function (done) {
            const cache = createCache(null, [
                {
                "ReplicationInstanceIdentifier": "gio-test-2",
                "ReplicationInstanceClass": "dms.t2.micro",
                "ReplicationInstanceStatus": "available",
                "AllocatedStorage": 5,
                "InstanceCreateTime": "2020-04-02T16:29:34.991Z",
                "VpcSecurityGroups": [
                    {
                        "VpcSecurityGroupId": "sg-588f0513",
                        "Status": "active"
                    }
                ],
                "AvailabilityZone": "us-east-1a",
                "ReplicationSubnetGroup": {
                    "ReplicationSubnetGroupIdentifier": "default-vpc-8a7c9cf0",
                    "ReplicationSubnetGroupDescription": "default group created by console for vpc id vpc-8a7c9cf0",
                    "VpcId": "vpc-8a7c9cf0",
                    "SubnetGroupStatus": "Complete",
                    "Subnets": [
                        {
                            "SubnetIdentifier": "subnet-00d54b39d82c253bf",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-00a354f3b627de72f",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0b03279f0fe7e554f",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-07f02957e441bde95",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-09a19d1207721a25a",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0774053c76031299e",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0b1019992ba7fed70",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0a73fa2127885acb6",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-08ce5ab7e15eb502c",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        }
                    ]
                },
                "PreferredMaintenanceWindow": "fri:06:34-fri:07:04",
                "PendingModifiedValues": {},
                "MultiAZ": false,
                "EngineVersion": "3.3.1",
                "AutoMinorVersionUpgrade": true,
                "KmsKeyId": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b",
                "ReplicationInstanceArn": "arn:aws:dms:us-east-1:1156999144843:rep:IP5IC7QARKU4GWDJDPQMGHKG5I",
                "ReplicationInstancePrivateIpAddress": "172.31.0.71",
                "ReplicationInstancePublicIpAddresses": [
                    null
                ],
                "ReplicationInstancePrivateIpAddresses": [
                    "172.31.0.71"
                ],
                "PubliclyAccessible": false
            }], [{
                "KeyId": "b4022674-ba90-4abc-9087-543cad09879b",
                "KeyArn": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b"
            }], null, {"b4022674-ba90-4abc-9087-543cad09879b": {
                    "data": {
                        "KeyMetadata": {
                            "AWSAccountId": "1156999144843",
                            "KeyId": "b4022674-ba90-4abc-9087-543cad09879b",
                            "Arn": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b",
                            "CreationDate": "2020-03-25T14:05:09.299Z",
                            "Enabled": true,
                            "Description": "Used for S3 encryption",
                            "KeyUsage": "ENCRYPT_DECRYPT",
                            "KeyState": "Enabled",
                            "Origin": "AWS_KMS",
                            "KeyManager": "CUSTOMER",
                            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
                            "EncryptionAlgorithms": [
                                "SYMMETRIC_DEFAULT"
                            ]
                        }
                    }
                }}, null, [{
                "AliasName": "alias/my-alias",
                "AliasArn": "arn:aws:kms:us-east-1:1156999144843:alias/my-alias",
                "TargetKeyId": "b4022674-ba90-4abc-9087-543cad09879b"
            }], null);
            dmsEncryptionEnabled.run(cache, {dms_encryption_kms_alias: 'alias/my-alias'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has encryption enabled using required KMS key')
                done();
            });
        });

        it('should FAIL if replication instance has encryption with default encryption', function (done) {
            const cache = createCache(null, [
                {
                "ReplicationInstanceIdentifier": "gio-test-2",
                "ReplicationInstanceClass": "dms.t2.micro",
                "ReplicationInstanceStatus": "available",
                "AllocatedStorage": 5,
                "InstanceCreateTime": "2020-04-02T16:29:34.991Z",
                "VpcSecurityGroups": [
                    {
                        "VpcSecurityGroupId": "sg-588f0513",
                        "Status": "active"
                    }
                ],
                "AvailabilityZone": "us-east-1a",
                "ReplicationSubnetGroup": {
                    "ReplicationSubnetGroupIdentifier": "default-vpc-8a7c9cf0",
                    "ReplicationSubnetGroupDescription": "default group created by console for vpc id vpc-8a7c9cf0",
                    "VpcId": "vpc-8a7c9cf0",
                    "SubnetGroupStatus": "Complete",
                    "Subnets": [
                        {
                            "SubnetIdentifier": "subnet-00d54b39d82c253bf",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-00a354f3b627de72f",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0b03279f0fe7e554f",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-07f02957e441bde95",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-09a19d1207721a25a",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0774053c76031299e",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0b1019992ba7fed70",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0a73fa2127885acb6",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-08ce5ab7e15eb502c",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        }
                    ]
                },
                "PreferredMaintenanceWindow": "fri:06:34-fri:07:04",
                "PendingModifiedValues": {},
                "MultiAZ": false,
                "EngineVersion": "3.3.1",
                "AutoMinorVersionUpgrade": true,
                "KmsKeyId": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b",
                "ReplicationInstanceArn": "arn:aws:dms:us-east-1:1156999144843:rep:IP5IC7QARKU4GWDJDPQMGHKG5I",
                "ReplicationInstancePrivateIpAddress": "172.31.0.71",
                "ReplicationInstancePublicIpAddresses": [
                    null
                ],
                "ReplicationInstancePrivateIpAddresses": [
                    "172.31.0.71"
                ],
                "PubliclyAccessible": false
            }], [{
                "KeyId": "b4022674-ba90-4abc-9087-543cad09879b",
                "KeyArn": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b"
            }], null, {"b4022674-ba90-4abc-9087-543cad09879b": {
                    "data": {
                        "KeyMetadata": {
                            "AWSAccountId": "1156999144843",
                            "KeyId": "b4022674-ba90-4abc-9087-543cad09879b",
                            "Arn": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b",
                            "CreationDate": "2020-03-25T14:05:09.299Z",
                            "Enabled": true,
                            "Description": "Default master key that protects my DMS replication instance volumes when no other key is defined",
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
                }}, null, [{
                "AliasName": "alias/aws/dms",
                "AliasArn": "arn:aws:kms:us-east-1:1156999144843:alias/aws/dms",
                "TargetKeyId": "b4022674-ba90-4abc-9087-543cad09879b"
            }], null);
            dmsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has default kms/dms encryption enabled')
                done();
            });
        });

        it('should PASS if replication instance has encryption with CMK encryption', function (done) {
            const cache = createCache(null, [
                {
                "ReplicationInstanceIdentifier": "gio-test-2",
                "ReplicationInstanceClass": "dms.t2.micro",
                "ReplicationInstanceStatus": "available",
                "AllocatedStorage": 5,
                "InstanceCreateTime": "2020-04-02T16:29:34.991Z",
                "VpcSecurityGroups": [
                    {
                        "VpcSecurityGroupId": "sg-588f0513",
                        "Status": "active"
                    }
                ],
                "AvailabilityZone": "us-east-1a",
                "ReplicationSubnetGroup": {
                    "ReplicationSubnetGroupIdentifier": "default-vpc-8a7c9cf0",
                    "ReplicationSubnetGroupDescription": "default group created by console for vpc id vpc-8a7c9cf0",
                    "VpcId": "vpc-8a7c9cf0",
                    "SubnetGroupStatus": "Complete",
                    "Subnets": [
                        {
                            "SubnetIdentifier": "subnet-00d54b39d82c253bf",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-00a354f3b627de72f",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0b03279f0fe7e554f",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-07f02957e441bde95",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-09a19d1207721a25a",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0774053c76031299e",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1a"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0b1019992ba7fed70",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-0a73fa2127885acb6",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1c"
                            },
                            "SubnetStatus": "Active"
                        },
                        {
                            "SubnetIdentifier": "subnet-08ce5ab7e15eb502c",
                            "SubnetAvailabilityZone": {
                                "Name": "us-east-1b"
                            },
                            "SubnetStatus": "Active"
                        }
                    ]
                },
                "PreferredMaintenanceWindow": "fri:06:34-fri:07:04",
                "PendingModifiedValues": {},
                "MultiAZ": false,
                "EngineVersion": "3.3.1",
                "AutoMinorVersionUpgrade": true,
                "KmsKeyId": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b",
                "ReplicationInstanceArn": "arn:aws:dms:us-east-1:1156999144843:rep:IP5IC7QARKU4GWDJDPQMGHKG5I",
                "ReplicationInstancePrivateIpAddress": "172.31.0.71",
                "ReplicationInstancePublicIpAddresses": [
                    null
                ],
                "ReplicationInstancePrivateIpAddresses": [
                    "172.31.0.71"
                ],
                "PubliclyAccessible": false
            }], [{
                "KeyId": "b4022674-ba90-4abc-9087-543cad09879b",
                "KeyArn": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b"
            }], null, {"b4022674-ba90-4abc-9087-543cad09879b": {
                    "data": {
                        "KeyMetadata": {
                            "AWSAccountId": "1156999144843",
                            "KeyId": "b4022674-ba90-4abc-9087-543cad09879b",
                            "Arn": "arn:aws:kms:us-east-1:1156999144843:key/b4022674-ba90-4abc-9087-543cad09879b",
                            "CreationDate": "2020-03-25T14:05:09.299Z",
                            "Enabled": true,
                            "Description": "Used for S3 encryption",
                            "KeyUsage": "ENCRYPT_DECRYPT",
                            "KeyState": "Enabled",
                            "Origin": "AWS_KMS",
                            "KeyManager": "CUSTOMER",
                            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
                            "EncryptionAlgorithms": [
                                "SYMMETRIC_DEFAULT"
                            ]
                        }
                    }
                }}, null, [{
                "AliasName": "alias/S3",
                "AliasArn": "arn:aws:kms:us-east-1:1156999144843:alias/S3",
                "TargetKeyId": "b4022674-ba90-4abc-9087-543cad09879b"
            }], null);
            dmsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has CMK encryption enabled')
                done();
            });
        });
    });
});
