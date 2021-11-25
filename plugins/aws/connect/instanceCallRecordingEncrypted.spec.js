var expect = require('chai').expect;
const instanceCallRecordingEncrypted = require('./instanceCallRecordingEncrypted');

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

const listInstanceCallRecordingStorageConfigs = [
    {
        "StorageConfigs": [
            {
                "AssociationId": "519cada57abf190bef871bb031d6c2813a0f76ffd638e531d1d7dd77984bd9a2",
                "StorageType": "S3",
                "S3Config": {
                    "BucketName": "amazon-connect-a72b5bc76263",
                    "BucketPrefix": "connect/akhtar/CallRecordings",
                    "EncryptionConfig": {
                        "EncryptionType": "KMS",
                        "KeyId": "arn:aws:kms:us-east-1:000111222333:key/2fe84bbe-30c3-4535-92b0-6d593085c84f"
                    }
                }
            }
        ]
    },
    {
        "StorageConfigs": [
            {
                "AssociationId": "519cada57abf190bef871bb031d6c2813a0f76ffd638e531d1d7dd77984bd9a2",
                "StorageType": "S3",
                "S3Config": {
                    "BucketName": "amazon-connect-a72b5bc76263",
                    "BucketPrefix": "connect/akhtar/CallRecordings",
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
            "Arn": "arn:aws:kms:us-east-1:000111222333:key/2fe84bbe-30c3-4535-92b0-6d593085c84f",
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
            "Arn": "arn:aws:kms:us-east-1:000111222333:key/2fe84bbe-30c3-4535-92b0-6d593085c84f",
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
        "KeyId": "2fe84bbe-30c3-4535-92b0-6d593085c84f",
        "KeyArn": "arn:aws:kms:us-east-1:000111222333:key/2fe84bbe-30c3-4535-92b0-6d593085c84f"
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
            listInstanceCallRecordingStorageConfigs: {
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

describe('instanceCallRecordingEncrypted', function () {
    describe('run', function () {
        it('should FAIL if Connect instance is not using desired encryption level', function (done) {
            const cache = createCache(listInstances, listInstanceCallRecordingStorageConfigs[0], listKeys, describeKey[1]);
            instanceCallRecordingEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Connect instance does not have encryption enabled for call recordings', function (done) {
            const cache = createCache(listInstances, listInstanceCallRecordingStorageConfigs[1], listKeys, describeKey[1]);
            instanceCallRecordingEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if Connect instance is using desired encryption level', function (done) {
            const cache = createCache(listInstances, listInstanceCallRecordingStorageConfigs[0], listKeys, describeKey[0]);
            instanceCallRecordingEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if Connect instance does not have any storage config for call recordings', function (done) {
            const cache = createCache(listInstances, listInstanceCallRecordingStorageConfigs[2], listKeys, describeKey[0]);
            instanceCallRecordingEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS no Connect instances found', function (done) {
            const cache = createCache([]);
            instanceCallRecordingEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN Unable to query Connect instances', function (done) {
            const cache = createCache([], null, listKeys, describeKey[0], { message: 'Unable to find data' });
            instanceCallRecordingEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN Unable to query KMS keys', function (done) {
            const cache = createCache(listInstances, listInstanceCallRecordingStorageConfigs[2], [], null, null, { message: 'Unable to find data' });
            instanceCallRecordingEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
