var assert = require('assert');
var expect = require('chai').expect;
var rds = require('./rdsEncryptionEnabled');

const listKeys = [
    {
        KeyId: '60c4f21b-e271-4e97-86ae-6403618a9467',
        KeyArn: 'arn:aws:kms:us-east-1:112233445566:key/60c4f21b-e271-4e97-86ae-6403618a9467'
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "112233445566",
            "KeyId": "60c4f21b-e271-4e97-86ae-6403618a9467",
            "Arn": "arn:aws:kms:us-east-1:112233445566:key/60c4f21b-e271-4e97-86ae-6403618a9467",
            "CreationDate": "2020-03-25T14:05:09.299Z",
            "Enabled": true,
            "Description": "Used for S3 encryption",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    }
];

const createCache = (rdsData, kmsData, listKeys, describeKey) => {
    var keyId = (listKeys && listKeys.length) ? listKeys[0].KeyId : null;
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: null,
                    data: rdsData
                }
            }
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    err: null,
                    data: kmsData
                }
            },
            listKeys: {
                'us-east-1': {
                    data: listKeys
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        data: describeKey
                    }
                }
            }
        }
    }
};

describe('rdsEncryptionEnabled', function () {
    describe('run', function () {
        it('should give passing result if no RDS instances are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No RDS instances found')
                done()
            };

            const cache = createCache(
                [], []
            );

            rds.run(cache, {}, callback);
        })

        it('should give passing result if encrypted RDS instance is found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Encryption at rest is enabled via KMS key')
                done()
            };

            const cache = createCache(
                [
                    {
                        Engine: 'mysql',
                        StorageEncrypted: true,
                        KmsKeyId: "arn:aws:kms:us-east-1:112233445566:key/60c4f21b-e271-4e97-86ae-6403618a9467",
                    }
                ],
                [],
                listKeys,
                describeKey[0]
            );

            rds.run(cache, {}, callback);
        })

        it('should give failing result if non-encrypted RDS instance is found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Encryption at rest is not enabled')
                done()
            };

            const cache = createCache(
                [
                    {
                        Engine: 'mysql',
                        StorageEncrypted: false
                    }
                ],
                []
            );

            rds.run(cache, {}, callback);
        })

        it('should give failing result if encrypted RDS instance is found with no KMS aliases', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('RDS KMS alias setting is configured but there are no KMS aliases')
                done()
            };

            const cache = createCache(
                [
                    {
                        Engine: 'mysql',
                        StorageEncrypted: true,
                        KmsKeyId: "arn:aws:kms:us-east-1:112233445566:key/abcdef10-1517-49d8-b085-77c50b904149",
                    }
                ],
                [],
                listKeys,
                describeKey[0]
            );

            rds.run(cache, {
                rds_encryption_kms_alias: 'alias/example1'
            }, callback);
        })

        it('should give failing result if encrypted RDS instance is found with wrong KMS aliases', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Encryption at rest is enabled, but is not using expected KMS key')
                done()
            };

            const cache = createCache(
                [
                    {
                        Engine: 'mysql',
                        StorageEncrypted: true,
                        KmsKeyId: "arn:aws:kms:us-east-1:112233445566:key/60c4f21b-e271-4e97-86ae-6403618a9467",
                    }
                ],
                [
                    {
                        AliasArn: "arn:aws:kms:us-east-1:112233445566:alias/example1", 
                        AliasName: "alias/example1", 
                        TargetKeyId: "def1234a-62d0-46c5-a7c0-5f3a3d2f8046"
                    }
                ],
                listKeys,
                describeKey[0]
            );

            rds.run(cache, {
                rds_encryption_kms_alias: 'alias/example1'
            }, callback);
        })

        it('should give passing result if encrypted RDS instance is found with correct KMS aliases', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Encryption at rest is enabled via expected KMS key')
                done()
            };

            const cache = createCache(
                [
                    {
                        Engine: 'mysql',
                        StorageEncrypted: true,
                        KmsKeyId: "arn:aws:kms:us-east-1:112233445566:key/60c4f21b-e271-4e97-86ae-6403618a9467",
                    }
                ],
                [
                    {
                        AliasArn: "arn:aws:kms:us-east-1:112233445566:alias/example1", 
                        AliasName: "alias/example1", 
                        TargetKeyId: "60c4f21b-e271-4e97-86ae-6403618a9467"
                    }
                ],
                listKeys,
                describeKey[0]
            );

            rds.run(cache, {
                rds_encryption_kms_alias: 'alias/example1'
            }, callback);
        })
    })
})