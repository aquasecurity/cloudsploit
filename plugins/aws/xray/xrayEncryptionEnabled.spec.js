var expect = require('chai').expect;
var xrayEncryptionEnabled = require('./xrayEncryptionEnabled');

var getEncryptionConfig = [
    {
        "KeyId": "arn:aws:kms:us-east-1:111122223333:key/a7c4862e-02e6-4a21-b0be-f2db95d6cf43",
        "Status": "ACTIVE",
        "Type": "KMS"
    }
];

var describeKey = [
    {
        "KeyMetadata": {
            "KeyId": "a7c4862e-02e6-4a21-b0be-f2db95d6cf43",
            "Arn": "arn:aws:kms:us-east-1:111122223333:key/a7c4862e-02e6-4a21-b0be-f2db95d6cf43",
            "Description": "Default master key that protects my X-Ray data when no other key is defined",
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

const createCache = (getEncryptionConfig, describeKey) => {
    return {
        xray: {
            getEncryptionConfig: {
                'us-east-1': {
                    data: getEncryptionConfig
                }
            }
        },
        kms: {
            describeKey: {
                'us-east-1': {
                    'a7c4862e-02e6-4a21-b0be-f2db95d6cf43': {
                        data: describeKey
                    }   
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        xray: {
            'us-east-1': {
                getEncryptionConfig: null
            }
        }
    }
}

describe('xrayEncryptionEnabled', function () {
    describe('run', function () {
        it('should FAIL if current encryption level is less than desired encryption level', function (done) {
            const cache = createCache(getEncryptionConfig[0], describeKey[0]);
            xrayEncryptionEnabled.run(cache, { xray_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if current encryption level is greater than or equal to desired encryption level', function (done) {
            const cache = createCache(getEncryptionConfig[0], describeKey[0]);
            xrayEncryptionEnabled.run(cache, { xray_encryption_level: 'awskms' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for XRay encryption configuration', function (done) {
            const cache = createCache(null);
            xrayEncryptionEnabled.run(cache, { xray_encryption_level: 'awskms' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if Unable to query KMS key', function (done) {
            const cache = createCache(getEncryptionConfig[0]);
            xrayEncryptionEnabled.run(cache, { xray_encryption_level: 'awskms' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should return nothing if get XRay encryption config result not found', function (done) {
            const cache = createNullCache();
            xrayEncryptionEnabled.run(cache, { xray_encryption_level: 'awskms' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
