var expect = require('chai').expect;
const instanceMediaStreamsEncrypted = require('./instanceMediaStreamsEncrypted');

const listInstances = [
    {
        "Id": "9da26b8e-8f9e-4af2-8717-6f79913f2439",
        "Arn": "arn:aws:connect:us-east-1:000111222333:instance/9da26b8e-8f9e-4af2-8717-6f79913f2439",
        "IdentityManagementType": "CONNECT_MANAGED",
        "InstanceAlias": "akhtar",
        "CreatedTime": "2021-11-24T17:07:05+05:00",
        "ServiceRole": "arn:aws:iam::000111222333:role/aws-service-role/connect.amazonaws.com/AWSServiceRoleForAmazonConnect_XYUbWO6kTpYfc9uUNk5i",
        "InstanceStatus": "ACTIVE",
        "InboundCallsEnabled": true,
        "OutboundCallsEnabled": false
    }
];

const listInstanceMediaStreamStorageConfigs = [
    {
        "StorageConfigs": [
            {
                "AssociationId": "d16cbba98243e2b092a214f262cb71ede51a8c94d2d58a02974d8590b43ddc8e",
                "StorageType": "KINESIS_VIDEO_STREAM",
                "KinesisVideoStreamConfig": {
                    "Prefix": "dedwed-connect-akhtar-contact-",
                    "RetentionPeriodHours": 1,
                    "EncryptionConfig": {
                        "EncryptionType": "KMS",
                        "KeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
                    }
                }
            }
        ]
    },
    {
        "StorageConfigs": [
            {
                "AssociationId": "d16cbba98243e2b092a214f262cb71ede51a8c94d2d58a02974d8590b43ddc8e",
                "StorageType": "KINESIS_VIDEO_STREAM",
                "S3Config": {
                    "KinesisVideoStreamConfig": {
                        "Prefix": "dedwed-connect-akhtar-contact-",
                        "RetentionPeriodHours": 1,
                        "EncryptionConfig": {
                            "EncryptionType": "KMS",
                            "KeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
                        }
                    }
                }
            }
        ]
    },
    {
        "StorageConfigs": []
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
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
            "Arn": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
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

const listKeys = [
    {
        "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "KeyArn": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
];

const createCache = (instances, storageConfig, keys, describeKey, instancesErr, keysErr) => {
    var instanceId = (instances && instances.length) ? instances[0].Id : null;
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    return {
        connect: {
            listInstances: {
                'us-east-1': {
                    data: instances,
                    err: instancesErr
                },
            },
            listInstanceMediaStreamStorageConfigs: {
                'us-east-1': {
                    [instanceId]: {
                        data: storageConfig
                    }
                }
            }
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
                        data: describeKey
                    },
                },
            }
        }
    };
};

describe('instanceMediaStreamsEncrypted', function () {
    describe('run', function () {
        it('should FAIL if Connect instance is not using desired encryption level', function (done) {
            const cache = createCache(listInstances, listInstanceMediaStreamStorageConfigs[0], listKeys, describeKey[1]);
            instanceMediaStreamsEncrypted.run(cache, {connect_media_streams_encryption_level: 'awscmk'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if Connect instance is using desired encryption level', function (done) {
            const cache = createCache(listInstances, listInstanceMediaStreamStorageConfigs[0], listKeys, describeKey[0]);
            instanceMediaStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if Connect instance does not have any storage config for media streams', function (done) {
            const cache = createCache(listInstances, listInstanceMediaStreamStorageConfigs[2], listKeys, describeKey[0]);
            instanceMediaStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS no Connect instances found', function (done) {
            const cache = createCache([]);
            instanceMediaStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN Unable to query Connect instances', function (done) {
            const cache = createCache([], null, listKeys, describeKey[0], { message: 'Unable to find data' });
            instanceMediaStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN Unable to query KMS keys', function (done) {
            const cache = createCache(listInstances, listInstanceMediaStreamStorageConfigs[2], [], null, null, { message: 'Unable to find data' });
            instanceMediaStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
