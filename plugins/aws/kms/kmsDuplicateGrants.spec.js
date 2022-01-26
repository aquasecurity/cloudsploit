var expect = require('chai').expect;
var kmsDuplicateGrants = require('./kmsDuplicateGrants');

const listGrants = [
    [
        {
            "KeyId": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
            "GrantId": "78c1e935fce8be9e146a049489e5e53301a88dfdf2a058e2843798b15c175251",
            "Name": "",
            "CreationDate": "2022-01-04T23:23:25+05:00",
            "GranteePrincipal": "arn:aws:iam::560213429563:root",
            "IssuingAccount": "arn:aws:iam::000011112222:root",
            "Operations": [
                "Decrypt",
                "Encrypt"
            ]
        }
    ],
    [
        {
            "KeyId": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
            "GrantId": "4c3205c326f01ce73a33185c095b8d862031307c535023122a4a9f472d00aaaa",
            "Name": "",
            "CreationDate": "2022-01-04T22:51:33+05:00",
            "GranteePrincipal": "arn:aws:iam::560213429563:root",
            "IssuingAccount": "arn:aws:iam::000011112222:root",
            "Operations": [
                "Decrypt",
                "Encrypt"
            ]
        },
        {
            "KeyId": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
            "GrantId": "78c1e935fce8be9e146a049489e5e53301a88dfdf2a058e2843798b15c175251",
            "Name": "",
            "CreationDate": "2022-01-04T23:23:25+05:00",
            "GranteePrincipal": "arn:aws:iam::560213429563:root",
            "IssuingAccount": "arn:aws:iam::000011112222:root",
            "Operations": [
                "Decrypt",
                "Encrypt"
            ]
        }
    ]
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "fb8ab834-47f3-4434-810a-e9cb1634de69",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
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

describe('kmsDuplicateGrants', function () {
    describe('run', function () {
        it('should PASS if KMS key does not have duplicate grants', function (done) {
            const cache = createCache([listKeys[0]], describeKey[0], listGrants[0]);
            kmsDuplicateGrants.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('KMS key does not have duplicate grants');
                done();
            });
        });

        it('should FAIL if KMS key has duplicate grants', function (done) {
            const cache = createCache([listKeys[0]], describeKey[0], listGrants[1]);
            kmsDuplicateGrants.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('KMS key has duplicate grants');
                done();
            });
        });

        it('should PASS if no grants exist for the KMS key', function (done) {
            const cache = createCache([listKeys[0]], describeKey[0], []);
            kmsDuplicateGrants.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No grants exist for the KMS key');
                done();
            });
        });

        it('should PASS if KMS key is AWS-managed', function (done) {
            const cache = createCache([listKeys[0]], describeKey[1], []);
            kmsDuplicateGrants.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('KMS key is AWS-managed');
                done();
            });
        });

        it('should PASS if No KMS keys found', function (done) {
            const cache = createCache([]);
            kmsDuplicateGrants.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No KMS keys found');
                done();
            });
        });

        it('should UNKNOWN if unable to query for KMS Key grants', function (done) {
            const cache = createCache([listKeys[0]], describeKey[0]);
            kmsDuplicateGrants.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for KMS Key grants');
                done();
            });
        });

        it('should UNKNOWN if unable to query for KMS Key', function (done) {
            const cache = createCache([listKeys[0]]);
            kmsDuplicateGrants.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for KMS Key');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache();
            kmsDuplicateGrants.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list KMS keys');
                done();
            });
        });
    });
});