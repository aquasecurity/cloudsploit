var expect = require('chai').expect;
var secretsManagerEncrypted = require('./secretsManagerEncrypted');

const createCacheNoSecrets = () => {
    return {
        secretsmanager: {
            listSecrets: {
                'us-east-1': {
                    data: [],
                },
            },
        },
    };
};

const createCacheAWSKMS = () => {
    return {
        secretsmanager: {
            listSecrets: {
                'us-east-1': {
                    data: [{
                        ARN: 'arn:aws:secretsmanager:us-east-1:111111111111:secret:testing-3eAAB5',
                    }],
                },
            },
        },
    };
};

const createCacheAWSCMK = () => {
    return {
        secretsmanager: {
            listSecrets: {
                'us-east-1': {
                    data: [{
                        ARN: 'arn:aws:secretsmanager:us-east-1:111111111111:secret:testing-3eAAB5',
                        KmsKeyId: 'mykey',
                    }],
                },
            },
        },
        kms: {
            describeKey: {
                'us-east-1': {
                    mykey: {
                        data: {
                            KeyMetadata: {
                                Origin: 'EXTERNAL',
                                KeyManager: 'CUSTOMER',
                            },
                        },
                    },
                },
            },
        },
    };
};

describe('secretsManagerEncrypted', function () {
    describe('run', function () {
        it('should PASS when there are no secrets', function (done) {
            const cache = createCacheNoSecrets();
            secretsManagerEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS when there are secrets and awskms is required encryption level', function (done) {
            const cache = createCacheAWSKMS();
            secretsManagerEncrypted.run(cache, { secretsmanager_minimum_encryption_level: 'awskms' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL when there are secrets using DefaultEncryptionKey and awscmk is required encryption level', function (done) {
            const cache = createCacheAWSKMS();
            secretsManagerEncrypted.run(cache, { secretsmanager_minimum_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS when there are secrets using awscmk and awscmk is required encryption level', function (done) {
            const cache = createCacheAWSCMK();
            secretsManagerEncrypted.run(cache, { secretsmanager_minimum_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
