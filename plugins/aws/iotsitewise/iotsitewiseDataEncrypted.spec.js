var expect = require('chai').expect;
var iotsitewiseDataEncrypted = require('./iotsitewiseDataEncrypted');

var describeDefaultEncryptionConfiguration = [
    {
        "encryptionType": "KMS_BASED_ENCRYPTION",
        "kmsKeyArn": "arn:aws:kms:us-east-1:101363889637:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "configurationStatus": {
            "state": "ACTIVE"
        }
    },
    {
        "encryptionType": "SITEWISE_DEFAULT_ENCRYPTION",
        "kmsKeyArn": null,
        "configurationStatus": { 
            "state": "ACTIVE"
        }
    }
];

const listKeys = [
    {
        "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
];

var describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my kinesis video data when no other key is defined",
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
            "Description": "Default master key that protects my kinesis video data when no other key is defined",
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

const createCache = (describeDefaultEncryptionConfiguration, keys, describeKey, describeDefaultEncryptionConfigurationErr, keysErr, describeKeyErr) => {
    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    return {
        iotsitewise: {
            describeDefaultEncryptionConfiguration: {
                'us-east-1': {
                    err: describeDefaultEncryptionConfigurationErr,
                    data: describeDefaultEncryptionConfiguration
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
                        err: describeKeyErr,
                        data: describeKey
                    }   
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        iotsitewise: {
            'us-east-1': {
                describeDefaultEncryptionConfiguration: null
            }
        }
    }
}

describe('iotsitewiseDataEncrypted', function () {
    describe('run', function () {
        it('should FAIL if current encryption level is less than desired encryption level', function (done) {
            const cache = createCache(describeDefaultEncryptionConfiguration[1], listKeys, describeKey[1]);
            iotsitewiseDataEncrypted.run(cache, {iot_sitewise_data_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if current encryption level is greater than or equal to desired encryption level', function (done) {
            const cache = createCache(describeDefaultEncryptionConfiguration[0], listKeys, describeKey[0]);
            iotsitewiseDataEncrypted.run(cache, { iot_sitewise_data_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for IoT SiteWise encryption configuration', function (done) {
            const cache = createCache(null);
            iotsitewiseDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if Unable to query KMS key', function (done) {
            const cache = createCache(describeDefaultEncryptionConfiguration[0]);
            iotsitewiseDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should return nothing if describe IoT SiteWise encryption config result not found', function (done) {
            const cache = createNullCache();
            iotsitewiseDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
