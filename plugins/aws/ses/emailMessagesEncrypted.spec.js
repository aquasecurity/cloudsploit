var expect = require('chai').expect;
var emailMessagesEncrypted = require('./emailMessagesEncrypted');

const describeActiveReceiptRuleSet = [
    {
        "ResponseMetadata": {
            "RequestId": "7c5c3ad1-cdbb-4e90-97d2-41c3f3e11e01"
        },
        "Metadata": {
            "Name": "aqua-ruleset",
            "CreatedTimestamp": "2021-11-12T14:56:59.226Z"
        },
        "Rules": [
            {
                "Name": "aqua-rule",
                "Enabled": true,
                "TlsPolicy": "Optional",
                "Recipients": [],
                "Actions": [
                    {
                        "S3Action": {
                            "BucketName": "aqua-data-bucket",
                            "ObjectKeyPrefix": "sesdata",
                            "KmsKeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
                        }
                    }
                ],
                "ScanEnabled": true
            }
        ]
    },
    {
        "ResponseMetadata": {
            "RequestId": "7c5c3ad1-cdbb-4e90-97d2-41c3f3e11e01"
        },
        "Metadata": {
            "Name": "aqua-ruleset",
            "CreatedTimestamp": "2021-11-12T14:56:59.226Z"
        },
        "Rules": [
            {
                "Name": "aqua-rule",
                "Enabled": true,
                "TlsPolicy": "Optional",
                "Recipients": [],
                "Actions": [
                    {
                        "S3Action": {
                            "BucketName": "aqua-data-bucket",
                            "ObjectKeyPrefix": "sesdata",
                        }
                    }
                ],
                "ScanEnabled": true
            }
        ]
    },
    {
        "ResponseMetadata": {
            "RequestId": "7c5c3ad1-cdbb-4e90-97d2-41c3f3e11e01"
        },
        "Metadata": {
            "Name": "aqua-ruleset",
            "CreatedTimestamp": "2021-11-12T14:56:59.226Z"
        },
        "Rules": [
            {
                "Name": "aqua-rule",
                "Enabled": false,
                "TlsPolicy": "Optional",
                "Recipients": [],
                "Actions": [
                    {
                        "S3Action": {
                            "BucketName": "aqua-data-bucket",
                            "ObjectKeyPrefix": "sesdata",
                            "KmsKeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
                        }
                    }
                ],
                "ScanEnabled": true
            }
        ]
    },
    {
        "ResponseMetadata": {
            "RequestId": "7c5c3ad1-cdbb-4e90-97d2-41c3f3e11e01"
        },
    },
    {
        "ResponseMetadata": {
            "RequestId": "7c5c3ad1-cdbb-4e90-97d2-41c3f3e11e01"
        },
        "Metadata": {
            "Name": "aqua-ruleset",
            "CreatedTimestamp": "2021-11-12T14:56:59.226Z"
        },
        "Rules": []
    },
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
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
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
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
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
    }
]

const createCache = (ruleSet, keys, describeKey, ruleSetErr, keysErr, describeKeyErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyArn.split('/')[1] : null;
    return {
        ses: {
            describeActiveReceiptRuleSet: {
                'us-east-1': {
                    data: ruleSet,
                    err: ruleSetErr
                }
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: keys,
                    err: keysErr
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        err: describeKeyErr,
                        data: describeKey
                    },
                },
            },
        },
    };
};

describe('emailMessagesEncrypted', function () {
    describe('run', function () {
        it('should PASS if SES active rule set rule is using desired encryption level', function (done) {
            const cache = createCache(describeActiveReceiptRuleSet[0], listKeys, describeKey[0]);
            emailMessagesEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if SES active rule set rule is not using desired encryption level', function (done) {
            const cache = createCache(describeActiveReceiptRuleSet[1], listKeys, describeKey[1]);
            emailMessagesEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if SES active rule set rule is not enabled', function (done) {
            const cache = createCache(describeActiveReceiptRuleSet[2], listKeys);
            emailMessagesEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no SES active rule set found', function (done) {
            const cache = createCache(describeActiveReceiptRuleSet[3]);
            emailMessagesEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if SES active rule set does not have any rules', function (done) {
            const cache = createCache(describeActiveReceiptRuleSet[4]);
            emailMessagesEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for SES active rule set', function (done) {
            const cache = createCache(describeActiveReceiptRuleSet[0], null, null, { message: "unable to query for SES active rule set" });
            emailMessagesEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(describeActiveReceiptRuleSet[0], null, null, null, { message: "Unable to list KMS keys" });
            emailMessagesEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
}) 