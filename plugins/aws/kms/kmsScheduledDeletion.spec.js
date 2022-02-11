var expect = require('chai').expect;
const kmsScheduledDeletion = require('./kmsScheduledDeletion');

const listKeys = [
    {
        KeyId: '60c4f21b-e271-4e97-86ae-6403618a9467',
        KeyArn: 'arn:aws:kms:us-east-1:112233445566:key/60c4f21b-e271-4e97-86ae-6403618a9467'
    }
];

const describeKey = [
    {
        KeyMetadata: {
            AWSAccountId: "111122223333", 
            Arn: "arn:aws:kms:us-east-1:111122223333:key/60c4f21b-e271-4e97-86ae-6403618a9467", 
            CreationDate: "2020-08-26T16:55:28+00:00", 
            CustomerMasterKeySpec: "SYMMETRIC_DEFAULT", 
            Description: "", 
            Enabled: true, 
            EncryptionAlgorithms: [
                "SYMMETRIC_DEFAULT"
            ], 
            KeyId: "60c4f21b-e271-4e97-86ae-6403618a9467", 
            KeyManager: "CUSTOMER", 
            KeyState: "PendingDeletion", 
            KeyUsage: "ENCRYPT_DECRYPT", 
            MultiRegion: false, 
            Origin: "AWS_KMS"
        }
    },
    {
        KeyMetadata: {
            AWSAccountId: "111122223333", 
            Arn: "arn:aws:kms:us-east-1:111122223333:key/60c4f21b-e271-4e97-86ae-6403618a9467", 
            CreationDate: "2020-08-26T16:55:28+00:00", 
            CustomerMasterKeySpec: "SYMMETRIC_DEFAULT", 
            Description: "", 
            Enabled: true, 
            EncryptionAlgorithms: [
                "SYMMETRIC_DEFAULT"
            ], 
            KeyId: "60c4f21b-e271-4e97-86ae-6403618a9467", 
            KeyManager: "CUSTOMER", 
            KeyState: "Enabled", 
            KeyUsage: "ENCRYPT_DECRYPT", 
            MultiRegion: false, 
            Origin: "AWS_KMS"
        }
    },
]

const createCache = (keys, describeKeys) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    return {
        kms:{
            listKeys: {
                'us-east-1': {
                    data: keys
                },
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        data: describeKeys
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        kms: {
            listKeys: {
                'us-east-1': {
                    err: {
                        message: 'error listing kms keys'
                    },
                },
            }, 
            describeKey: {
                'us-east-1': {
                    err: {
                        message: 'error listing kms key resources'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        kms: {
            listKeys: {
                'us-east-1': null,
            },
            describeKey: {
                'us-east-1': null
            },
        },
    };
};

describe('kmsScheduledDeletion', function () {
    describe('run', function () {
        it('should WARN if Key is scheduled for deletion', function (done) {
            const cache = createCache([listKeys[0]], describeKey[0]);
            kmsScheduledDeletion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).to.include('Key is scheduled for deletion');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if Key is not scheduled for deletion', function (done) {
            const cache = createCache([listKeys[0]], describeKey[1]);
            kmsScheduledDeletion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key is not scheduled for deletion');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no KMS keys found', function (done) {
            const cache = createCache([], describeKey[0]);
            kmsScheduledDeletion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No KMS keys found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createErrorCache();
            kmsScheduledDeletion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list KMS keys');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return any result if list keys response is not found', function (done) {
            const cache = createNullCache();
            kmsScheduledDeletion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});