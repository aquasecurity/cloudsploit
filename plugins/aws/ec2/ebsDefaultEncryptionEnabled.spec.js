var expect = require('chai').expect;
var ebsDefaultEncryptionEnabled = require('./ebsDefaultEncryptionEnabled');

const createCache = (boolValue) => {
    return {
        ec2: {
            getEbsEncryptionByDefault: {
                'us-east-1': {
                    data: boolValue,
                }
            },
            getEbsDefaultKmsKeyId: {
                'us-east-1': {
                    data: 'key/0987dcba-09fe-87dc-65ba-ab0987654321',
                }
            },
        },
        kms: {
            describeKey: {
                'us-east-1': {
                    '0987dcba-09fe-87dc-65ba-ab0987654321': {
                        data: {
                            KeyMetadata: {
                                Origin: 'AWS_KMS',
                                KeyManager: 'CUSTOMER',
                            },
                        }
                    },
                }
            },
            listAliases: {
                'us-east-1': {
                        data: [],
                }
            },
            listKeys: {
                'us-east-1': {
                    data: [
                        {
                            'KeyId': '0987dcba-09fe-87dc-65ba-ab0987654321',
                            'KeyArn': 'arn:aws:kms:us-east-1:0123456789101:key/0987dcba-09fe-87dc-65ba-ab0987654321'
                        }
                    ]
                }
            },
        },
    };
};


describe('ebsDefaultEncryptionEnabled', function () {
    describe('run', function () {
        it('should FAIL if ebs encryption by default is disabled', function (done) {
            const cache = createCache(false);
            const settings = {};

            ebsDefaultEncryptionEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if ebs encryption by default is enabled, with detail on "encryption level"', function (done) {
            const cache = createCache(true);
            const settings = {};

            ebsDefaultEncryptionEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if ebs encryption level is "lower" than target encryption level', function (done) {
            const cache = createCache(true);
            const settings = {
                ebs_encryption_level: 'cloudhsm',
            };

            ebsDefaultEncryptionEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
    });
});
