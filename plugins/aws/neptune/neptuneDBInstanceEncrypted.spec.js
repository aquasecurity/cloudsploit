var expect = require('chai').expect;
var neptuneDBInstanceEncrypted = require('./neptuneDBInstanceEncrypted');

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
        "LatestRestorableTime": "2021-11-16T09:01:51.536000+00:00",
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
    }
];

const listKeys = [
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
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
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
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

const createCache = (clusters, keys, describeKey, clustersErr, keysErr, describeKeyErr) => {
    var keyId = (clusters && clusters.length && clusters[0].KmsKeyId) ? clusters[0].KmsKeyId.split('/')[1] : null;
    return {
        neptune: {
            describeDBClusters: {
                'us-east-1': {
                    err: clustersErr,
                    data: clusters
                },
            },
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
        },
    };
};



describe('neptuneDBInstanceEncrypted', function () {
    describe('run', function () {
        it('should PASS if Neptune database instance is encrypted with desired encryption level', function (done) {
            const cache = createCache(describeDBClusters, listKeys, describeKey[0]);
            neptuneDBInstanceEncrypted.run(cache, { neptunedb_cluster_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Neptune database instance is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should FAIL if Neptune database instance is not encrypted with desired encyption level', function (done) {
            const cache = createCache(describeDBClusters, listKeys, describeKey[1]);
            neptuneDBInstanceEncrypted.run(cache, { neptunedb_cluster_desired_encryption_level:'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Neptune database instance is encrypted with awskms');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should PASS if no Neptune database instances found', function (done) {
            const cache = createCache([]);
            neptuneDBInstanceEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Neptune database instances found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Neptune Database instances', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Neptune database instances" });
            neptuneDBInstanceEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list KMS keys" });
            neptuneDBInstanceEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
