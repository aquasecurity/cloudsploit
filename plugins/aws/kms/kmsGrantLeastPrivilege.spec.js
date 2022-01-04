var expect = require('chai').expect;
var kmsGrantLeastPrivilege = require('./kmsGrantLeastPrivilege');

const listGrants = [
    [
        {
            "KeyId": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "GrantId": "02c191300546eb259de3e7c4c29be970bdc8b0a209af7d27581d87df37310068",
            "Name": "Allperm",
            "CreationDate": "2021-11-22T14:34:45+05:00",
            "GranteePrincipal": "AROARSNYOUG3BVO636KMQ",
            "IssuingAccount": "arn:aws:iam::108297888182:root",
            "Operations": [
                "Decrypt",
                "Encrypt",
                "GenerateDataKey",
                "GenerateDataKeyWithoutPlaintext",
                "ReEncryptFrom",
                "ReEncryptTo",
                "CreateGrant",
                "RetireGrant",
                "DescribeKey",
                "GenerateDataKeyPair",
                "GenerateDataKeyPairWithoutPlaintext"
            ]
        },
        {
            "KeyId": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "GrantId": "04df4a33699d9a76c3baed37ea9b95ee25328236952c6833810cfae0a751686e",
            "Name": "aws:profile:domains/mine2-AppFlow",
            "CreationDate": "2021-11-19T14:43:41+05:00",
            "GranteePrincipal": "profile.us-east-1.amazonaws.com",
            "RetiringPrincipal": "profile.us-east-1.amazonaws.com",
            "IssuingAccount": "arn:aws:iam::000011112222:root",
            "Operations": [
                "Decrypt"
            ]
        },
        {
            "KeyId": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "GrantId": "0978f48c86e449fc2c64f2440313813393909e43963ec3a2e457bbfe0e38b19d",
            "Name": "aws:profile:domains/mine2",
            "CreationDate": "2021-11-19T14:43:41+05:00",
            "GranteePrincipal": "profile.us-east-1.amazonaws.com",
            "RetiringPrincipal": "profile.us-east-1.amazonaws.com",
            "IssuingAccount": "arn:aws:iam::000011112222:root",
            "Operations": [
                "Decrypt",
                "GenerateDataKey",
                "RetireGrant"
            ],
            "Constraints": {
                "EncryptionContextEquals": {
                    "aws:profile:domain": "mine2"
                }
            }
        }
    ],
    [
        {
            "KeyId": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
            "GrantId": "1521390bb3dcbdf8a5754cffcd2f3ce45e5f15d724d70f11ca53ccbfa9bfda6e",
            "Name": "",
            "CreationDate": "2022-01-04T17:33:32+05:00",
            "GranteePrincipal": "arn:aws:iam::560213429563:root",
            "IssuingAccount": "arn:aws:iam::000011112222:root",
            "Operations": [
                "Decrypt"
            ]
        },
        {
            "KeyId": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
            "GrantId": "a752caf60c95a013f6318e0f9d1f3a8a202f14f9ff9569af4bd338eddc1f19c5",
            "Name": "",
            "CreationDate": "2022-01-04T17:27:13+05:00",
            "GranteePrincipal": "arn:aws:iam::560213429563:root",
            "IssuingAccount": "arn:aws:iam::000011112222:root",
            "Operations": [
                "Decrypt"
            ]
        }
    ]
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
            "KeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "fb8ab834-47f3-4434-810a-e9cb1634de69",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
            "CreationDate": "2022-01-04T20:45:32.105000+05:00",
            "Enabled": true,
            "Description": "",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "RSA_2048",
            "KeySpec": "RSA_2048",
            "EncryptionAlgorithms": [
                "RSAES_OAEP_SHA_1",
                "RSAES_OAEP_SHA_256"
            ],
            "MultiRegion": false
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
    },
    {
        "KeyId": "fb8ab834-47f3-4434-810a-e9cb1634de69",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69"
    }
]

const createCache = (keys, describeKey, listGrants) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;

    return {
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
            listGrants: {
                'us-east-1': {
                    [keyId]: {
                        data: {
                            Grants: listGrants
                        },
                        err: null,
                    },
                },
            }
        },
    };
};

describe('kmsGrantLeastPrivilege', function () {
    describe('run', function () {
        it('should PASS if KMS key does not provide * permission for any grants', function (done) {
            const cache = createCache([listKeys[1]], describeKey[1], listGrants[1]);
            kmsGrantLeastPrivilege.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('KMS key does not provide * permission for any grants');
                done();
            });
        });

        it('should FAIL if KMS key provides * permission for grants', function (done) {
            const cache = createCache([listKeys[0]], describeKey[0], listGrants[0]);
            kmsGrantLeastPrivilege.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('KMS key provides * permission for these grants');
                done();
            });
        });

        it('should PASS if no grants exist for the KMS key', function (done) {
            const cache = createCache([listKeys[1]], describeKey[1], []);
            kmsGrantLeastPrivilege.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No grants exist for the KMS key');
                done();
            });
        });

        it('should PASS if KMS key is AWS-managed', function (done) {
            const cache = createCache([listKeys[0]], describeKey[2], []);
            kmsGrantLeastPrivilege.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('KMS key is AWS-managed');
                done();
            });
        });

        it('should PASS if No KMS keys found', function (done) {
            const cache = createCache([]);
            kmsGrantLeastPrivilege.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No KMS keys found');
                done();
            });
        });

        it('should UNKNOWN if unable to query for KMS Key grants', function (done) {
            const cache = createCache([listKeys[1]], describeKey[1]);
            kmsGrantLeastPrivilege.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for KMS Key grants');
                done();
            });
        });

        it('should UNKNOWN if unable to query for KMS Key', function (done) {
            const cache = createCache([listKeys[1]]);
            kmsGrantLeastPrivilege.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for KMS Key');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache();
            kmsGrantLeastPrivilege.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list KMS keys');
                done();
            });
        });
    });
});
