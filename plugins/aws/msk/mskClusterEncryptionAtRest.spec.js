var expect = require('chai').expect;
var mskClusterEncryptionAtRest = require('./mskClusterEncryptionAtRest');

const listClusters = [
    { 
        "BrokerNodeGroupInfo": {
          "BrokerAZDistribution": "DEFAULT",
            "ClientSubnets": [
                "subnet-02ed4181800d4658b",
                "subnet-06629b4200870c740"
            ],
            "InstanceType": "kafka.m5.large",
            "SecurityGroups": [
                "sg-0cb6c99daaa6b73c5"
            ],
            "StorageInfo": {
                "EbsStorageInfo": {
                    "VolumeSize": 100
                }
            }
        },
        "ClientAuthentication": {
            "Sasl": {
                "Scram": {
                    "Enabled": false
                },
                "Iam": {
                    "Enabled": true
                }
            },
            "Tls": {
                "CertificateAuthorityArnList": [],
                "Enabled": false
            },
            "Unauthenticated": {
                "Enabled": true
            }
        },
        "ClusterArn": "arn:aws:kafka:us-east-1:000111222333:cluster/sadeed-cl1/444e81bf-14ab-4839-923e-ac424325e2df-20",
        "ClusterName": "sadeed-cl1",
        "CreationTime": "2021-11-16T10:49:45.001000+00:00",
        "CurrentBrokerSoftwareInfo": {
            "KafkaVersion": "2.6.2"
        },
        "CurrentVersion": "K1VC38T7YXB528",
        "EncryptionInfo": {
            "EncryptionAtRest": {
                "DataVolumeKMSKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
            },
            "EncryptionInTransit": {
                "ClientBroker": "TLS_PLAINTEXT",
                "InCluster": true
            }
        },
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
    var keyId = (clusters && clusters.length && clusters[0].EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId) ? clusters[0].EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId.split('/')[1] : null;
    return {
        kafka: {
            listClusters: {
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




describe('mskClusterEncryptionAtRest', function () {
    describe('run', function () {
        it('should PASS if MSK Cluster At-Rest is encrypted with desired encryption level', function (done) {
            const cache = createCache(listClusters, listKeys, describeKey[0]);
            mskClusterEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('MSK cluster is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should FAIL if MSK Cluster At-Rest is not encrypted with desired encyption level', function (done) {
            const cache = createCache(listClusters, listKeys, describeKey[1]);
            mskClusterEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('MSK cluster is encrypted with awskms');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should PASS if No MSK Clusters found', function (done) {
            const cache = createCache([]);
            mskClusterEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No MSK clusters found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list MSK Clusters', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list  MSK clusters" });
            mskClusterEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list KMS keys" });
            mskClusterEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
