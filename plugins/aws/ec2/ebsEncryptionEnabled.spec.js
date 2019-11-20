var expect = require('chai').expect;
var ebsEncryptionEnabled = require('./ebsEncryptionEnabled')

const createCache = (volumes, keys) => {
    return {
        ec2: {
            describeVolumes: {
                'us-east-1': {
                    data: volumes,
                },
            },
        },
        kms: {
            describeKey: {
                'us-east-1': keys,
            },
        },
    };
};

describe('ebsEncryptionEnabled', function () {
    describe('run', function () {
        it('should FAIL if volume is not encrypted', function (done) {
            const cache = createCache([{
                VolumeId: 'abc123',
                Encrypted: false,
            }], {
                'mykmskey': {
                    data: {
                        KeyMetadata: {
                            Origin: 'AWS_KMS',
                            KeyManager: 'AWS',
                        },
                    },
                },
            });
            const settings = {
                ebs_encryption_level: 'awscmk',
            };

            ebsEncryptionEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done()
            });
        });

        it('should WARN if encryption level is less than configured setting', function (done) {
            const cache = createCache([{
                VolumeId: 'abc123',
                Encrypted: true,
                KmsKeyId: 'arn:aws:kms:us-east-1:123412341234:key/mykmskey',
            }], {
                'mykmskey': {
                    data: {
                        KeyMetadata: {
                            Origin: 'AWS_KMS',
                            KeyManager: 'AWS',
                        },
                    },
                },
            });
            const settings = {
                ebs_encryption_level: 'awscmk',
            };

            ebsEncryptionEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1, 'bad status');
                done()
            });
        });

        it('should PASS if encryption level meets configured target setting', function (done) {
            const cache = createCache([{
                VolumeId: 'abc123',
                Encrypted: true,
                KmsKeyId: 'arn:aws:kms:us-east-1:123412341234:key/mykmskey',
            }], {
                'mykmskey': {
                    data: {
                        KeyMetadata: {
                            Origin: 'AWS_KMS',
                            KeyManager: 'AWS',
                        },
                    },
                },
            });
            const settings = {
                ebs_encryption_level: 'awskms',
            };

            ebsEncryptionEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON if encryption level meets configured target setting', function (done) {
            const cache = createCache([{
                VolumeId: 'abc123',
                Encrypted: true,
                KmsKeyId: 'arn:aws:kms:us-east-1:123412341234:key/mykmskey',
            }], {
                'mykmskey': {
                    data: {
                        KeyMetadata: {
                            Origin: 'AWS_KMS',
                            KeyManager: 'AWS',
                        },
                    },
                },
            });
            const settings = {
                ebs_encryption_level: 'awskms',
            };

            ebsEncryptionEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
