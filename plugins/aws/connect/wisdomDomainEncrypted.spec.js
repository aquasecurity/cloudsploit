var expect = require('chai').expect;
var wisdomDomainEncrypted = require('./wisdomDomainEncrypted');

const listAssistants = [
    {
      assistantArn: 'arn:aws:wisdom:us-east-1:111122223333:assistant/6abcbdde-4a11-42b1-a79c-18e1e7d554c3',
      assistantId: '6abcbdde-4a11-42b1-a79c-18e1e7d554c3',
      name: 'asdw',
      serverSideEncryptionConfiguration: {
        kmsKeyId: 'arn:aws:kms:us-east-1:111122223333:key/ad013a33-b01d-4d88-ac97-127399c18b3e'
      },
      status: 'ACTIVE',
      tags: {},
      type: 'AGENT'
    },
    {
        assistantArn: 'arn:aws:wisdom:us-east-1:111122223333:assistant/6abcbdde-4a11-42b1-a79c-18e1e7d554c3',
        assistantId: '6abcbdde-4a11-42b1-a79c-18e1e7d554c3',
        name: 'asdw',
        serverSideEncryptionConfiguration: {
          kmsKeyId: 'arn:aws:kms:us-east-1:111122223333:key/22322a33-b01d-4d88-ac97-127399c18b3e'
        },
        status: 'ACTIVE',
        tags: {},
        type: 'AGENT'
    },
    {
      assistantArn: 'arn:aws:wisdom:us-east-1:111122223333:assistant/e5b466a7-52e6-480d-a145-965ba1882c18',
      assistantId: 'e5b466a7-52e6-480d-a145-965ba1882c18',
      name: 'ddwe',
      status: 'ACTIVE',
      tags: {},
      type: 'AGENT'
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
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
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
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
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
]

const createCache = (domains, keys, describeKey) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;

    return {
        wisdom: {
            listAssistants: {
                'us-east-1': {
                    err: null,
                    data: domains
                },
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

describe('wisdomDomainEncrypted', function () {
    describe('run', function () {
        it('should PASS if Wisdom domain is encrypted with desired encryption level', function (done) {
            const cache = createCache([listAssistants[0]], listKeys, describeKey[0]);
            wisdomDomainEncrypted.run(cache, { wisdom_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Wisdom domain is not encrypted with desired encryption level', function (done) {
            const cache = createCache([listAssistants[0]], listKeys, describeKey[1]);
            wisdomDomainEncrypted.run(cache, { wisdom_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Wisdom domain is found', function (done) {
            const cache = createCache([]);
            wisdomDomainEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Wisdom domains', function (done) {
            const cache = createCache(null, null, null);
            wisdomDomainEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to find Wisdom domain encryption key', function (done) {
            const cache = createCache([listAssistants[2]], null, null);
            wisdomDomainEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listAssistants, null, null);
            wisdomDomainEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})
