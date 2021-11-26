var expect = require('chai').expect;
var memorydbClusterEncrypted = require('./memorydbClusterEncrypted');

const describeClusters = [
    {
        "Name": "aquacluster",
        "Status": "creating",
        "NumberOfShards": 1,
        "ClusterEndpoint": {
            "Port": 6379
        },
        "NodeType": "db.r6g.large",
        "EngineVersion": "6.2",
        "EnginePatchVersion": "6.2.4",
        "ParameterGroupName": "default.memorydb-redis6",
        "ParameterGroupStatus": "in-sync",
        "SecurityGroups": [
            {
                "SecurityGroupId": "sg-0cb6c99daaa6b73c5",
                "Status": "active"
            }
        ],
        "SubnetGroupName": "subnet1",
        "TLSEnabled": true,
        "ARN": "arn:aws:memorydb:us-east-1:000111222333:cluster/aquacluster",
        "SnapshotRetentionLimit": 1,
        "MaintenanceWindow": "wed:08:00-wed:09:00",
        "SnapshotWindow": "06:30-07:30",
        "ACLName": "open-access",
        "AutoMinorVersionUpgrade": true
    },
    {
        "Name": "sadeed-cl1",
        "Status": "available",
        "NumberOfShards": 1,
        "ClusterEndpoint": {
            "Address": "clustercfg.sadeed-cl1.zvodgj.memorydb.us-east-1.amazonaws.com",
            "Port": 6379
        },
        "NodeType": "db.r6g.large",
        "EngineVersion": "6.2",
        "EnginePatchVersion": "6.2.4",
        "ParameterGroupName": "default.memorydb-redis6",
        "ParameterGroupStatus": "in-sync",
        "SecurityGroups": [
            {
                "SecurityGroupId": "sg-0cb6c99daaa6b73c5",
                "Status": "active"
            }
        ],
        "SubnetGroupName": "subnet1",
        "TLSEnabled": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "ARN": "arn:aws:memorydb:us-east-1:000111222333:cluster/sadeed-cl1",
        "SnapshotRetentionLimit": 1,
        "MaintenanceWindow": "tue:06:00-tue:07:00",
        "SnapshotWindow": "04:00-05:00",
        "ACLName": "open-access",
        "AutoMinorVersionUpgrade": true
    }
];

const listKeys = [
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
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
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
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

const createCache = (clusters, keys, describeKey, logGroupErr, keysErr, describeKeyErr) => {
    var keyId = (clusters && clusters.length && clusters[0].KmsKeyId) ? clusters[0].KmsKeyId.split('/')[1] : null;
    return {
        memorydb: {
            describeClusters: {
                'us-east-1': {
                    err: logGroupErr,
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


describe('memorydbClusterEncrypted', function () {
    describe('run', function () {
        it('should PASS if MemoryDB Cluster for Redis is encrypted with desired encryption level', function (done) {
            const cache = createCache([describeClusters[1]], listKeys, describeKey[0]);
            memorydbClusterEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('MemoryDB cluster is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if MemoryDB Cluster for Redis is not encrypted with desired encyption level', function (done) {
            const cache = createCache([describeClusters[0]], listKeys, describeKey[1]);
            memorydbClusterEncrypted.run(cache, {} , (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('MemoryDB cluster is encrypted with awskms');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no No MemoryDB Cluster found', function (done) {
            const cache = createCache([]);
            memorydbClusterEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No MemoryDB clusters found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list MemoryDB Clusters', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list MemoryDB clusters" });
            memorydbClusterEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list KMS keys" });
            memorydbClusterEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
}); 
