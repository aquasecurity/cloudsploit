var expect = require('chai').expect;
var ebsDefaultEncryptionEnabled = require('./ebsDefaultEncryptionEnabled');

const createCache = (boolValue) => {
    return {
        ec2: {
            getEbsEncryptionByDefault: {
                'us-east-1': {
                    data: boolValue,
                },
                'us-east-2': {
                    data: boolValue,
                },
            },
            getEbsDefaultKmsKeyId: {
                'us-east-1': {
                    data: 'foo/0987dcba-09fe-87dc-65ba-ab0987654321',
                },
                'us-east-2': {
                    data: 'alias/aws/ebs',
                },
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
                },
                'us-east-2': {
                    '1234abcd-12ab-34cd-56ef-1234567890ab': {
                        data: {
                            KeyMetadata: {
                                Origin: 'AWS_KMS',
                                KeyManager: 'AWS',
                            },
                        },
                    },
                },
            },
            listAliases: {
                'us-east-1': {
                        data: [],
                },
                'us-east-2': {
                        data: [{
                            AliasName: 'alias/aws/ebs', TargetKeyId: '1234abcd-12ab-34cd-56ef-1234567890ab'
                        }],
                },
            },
            listKeys: {
                'us-east-1': {
                    data: [
                        {
                            'KeyId': '0987dcba-09fe-87dc-65ba-ab0987654321',
                            'KeyArn': 'arn:aws:kms:us-east-1:0123456789101:key/0987dcba-09fe-87dc-65ba-ab0987654321'
                        }
                    ]
                },
                'us-east-2': {
                    data: [
                        {
                            'KeyId': '1234abcd-12ab-34cd-56ef-1234567890ab',
                            'KeyArn': 'arn:aws:kms:us-east-2:0123456789101:key/1234abcd-12ab-34cd-56ef-1234567890ab'
                        }
                    ]
                },
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
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should PASS if ebs encryption by default is enabled, with detail on "encryption level"', function (done) {
            const cache = createCache(true);
            const settings = {};

            ebsDefaultEncryptionEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if ebs encryption level is "lower" than target encryption level', function (done) {
            const cache = createCache(true);
            const settings = {
                ebs_encryption_level: 'cloudhsm',
            };

            ebsDefaultEncryptionEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });
    });
});
