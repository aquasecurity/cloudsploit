var expect = require('chai').expect;
const fraudDetectorDataEncrypted = require('./fraudDetectorDataEncrypted');

const getDetectors = [
    {
        "detectorId": "qwdqw",
        "eventTypeName": "asda",
        "lastUpdatedTime": "2021-11-29T15:55:31.116Z",
        "createdTime": "2021-11-29T15:55:31.116Z",
        "arn": "arn:aws:frauddetector:us-east-1:111222333444:detector/qwdqw"
    },
    {
        "detectorId": "test_detector",
        "description": "Testing Detectors",
        "eventTypeName": "test",
        "lastUpdatedTime": "2021-12-16T13:10:44.896Z",
        "createdTime": "2021-12-16T12:57:03.748Z",
        "arn": "arn:aws:frauddetector:us-east-1:111222333444:detector/test_detector"
    }
];

const getKMSEncryptionKeyCMK = {
    "kmsEncryptionKeyArn": "arn:aws:kms:us-east-1:111222333444:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
};

const getKMSEncryptionKeyAWSKMS = {
    "kmsEncryptionKeyArn": "DEFAULT"
}

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:111222333444:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
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

const createCache = (fraudDetectors, fraudKMSEncryptionKey, keys, describeKey) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;

    return {
        frauddetector: {
            getDetectors: {
                'us-east-1': {
                    err: null,
                    data: fraudDetectors
                },
            },
            getKMSEncryptionKey: {
              'us-east-1': {
                err: null,
                data: fraudKMSEncryptionKey
              }
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: keys,
                    err: null
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        err: null,
                        data: describeKey
                    },
                },
            },
        },
    };
};

describe('fraudDetectorDataEncrypted', function () {
    describe('run', function () {
        it('should PASS if Fraud Detector data is encrypted with desired encryption level', function (done) {
            const cache = createCache(getDetectors, getKMSEncryptionKeyCMK, listKeys, describeKey[0]);
            fraudDetectorDataEncrypted.run(cache, { fraud_detector_data_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Fraud Detector data is not encrypted with desired encryption level', function (done) {
            const cache = createCache(getDetectors, getKMSEncryptionKeyAWSKMS, listKeys, describeKey[1]);
            fraudDetectorDataEncrypted.run(cache, { fraud_detector_data_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Fraud Detector data is found', function (done) {
            const cache = createCache([]);
            fraudDetectorDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Fraud Detector data', function (done) {
            const cache = createCache();
            fraudDetectorDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query Fraud Detectors Key', function (done) {
            const cache = createCache();
            fraudDetectorDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(getDetectors, null, null);
            fraudDetectorDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
