var expect = require('chai').expect;
var voiceIdDomainEncrypted = require('./voiceIdDomainEncrypted');

const listDomains = [
    {
      Arn: 'arn:aws:voiceid:us-east-1:111222333:domain/aabbccddeeff',
      CreatedAt: '2021-11-29T14:00:40.764Z',
      DomainId: 'aabbccddeeff',
      DomainStatus: 'ACTIVE',
      Name: 'akhtar-domain',
      ServerSideEncryptionConfiguration: {
        KmsKeyId: 'arn:aws:kms:us-east-1:112222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e'
      },
      UpdatedAt: '2021-11-29T14:00:41.007Z'
    },
    {
      Arn: 'arn:aws:voiceid:us-east-1:111222333:domain/0asdfvv02ddff',
      CreatedAt: '2021-12-05T09:11:34.154Z',
      DomainId: '0asdfvv02ddff',
      DomainStatus: 'ACTIVE',
      Name: 'bdjasd',
      ServerSideEncryptionConfiguration: {
        KmsKeyId: 'arn:aws:kms:us-east-1:112233:key/ad013a33-b01d-4d88-ac97-127399c18b3e'
      },
      UpdatedAt: '2021-12-05T09:11:34.465Z'
    },
    {
      Arn: 'arn:aws:voiceid:us-east-1:111222333:domain/aa112ccc33vv',
      CreatedAt: '2021-12-12T20:48:49.447Z',
      DomainId: 'aa112ccc33vv',
      DomainStatus: 'ACTIVE',
      Name: 'Test',
      ServerSideEncryptionConfiguration: {
        KmsKeyId: 'arn:aws:kms:us-east-1:1122233:key/ad013a33-b01d-4d88-ac97-127399c18b3e'
      },
      UpdatedAt: '2021-12-12T20:48:49.666Z'
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
        voiceid: {
            listDomains: {
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

describe('voiceIdDomainEncrypted', function () {
    describe('run', function () {
        it('should PASS if VoiceID domain is encrypted with desired encryption level', function (done) {
            const cache = createCache(listDomains, listKeys, describeKey[0]);
            voiceIdDomainEncrypted.run(cache, { voice_id_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(3);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if VoiceID domain is not encrypted with desired encryption level', function (done) {
            const cache = createCache(listDomains, listKeys, describeKey[1]);
            voiceIdDomainEncrypted.run(cache, { voice_id_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(3);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no VoiceID domain is found', function (done) {
            const cache = createCache([]);
            voiceIdDomainEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list VoiceID domains', function (done) {
            const cache = createCache(null, null, null);
            voiceIdDomainEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listDomains, null, null);
            voiceIdDomainEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})
