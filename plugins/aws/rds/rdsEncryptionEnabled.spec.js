var assert = require('assert');
var expect = require('chai').expect;
var rds = require('./rdsEncryptionEnabled');

const createCache = (rdsData, kmsData) => {
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
                        KmsKeyId: "arn:aws:kms:us-east-1:012345678910:key/abcdef10-1517-49d8-b085-77c50b904149",
                    }
                ],
                []
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
                        KmsKeyId: "arn:aws:kms:us-east-1:012345678910:key/abcdef10-1517-49d8-b085-77c50b904149",
                    }
                ],
                []
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
                        KmsKeyId: "arn:aws:kms:us-east-1:012345678910:key/abcdef10-1517-49d8-b085-77c50b904149",
                    }
                ],
                [
                    {
                        AliasArn: "arn:aws:kms:us-east-1:012345678910:alias/example1", 
                        AliasName: "alias/example1", 
                        TargetKeyId: "def1234a-62d0-46c5-a7c0-5f3a3d2f8046"
                    }
                ]
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
                        KmsKeyId: "arn:aws:kms:us-east-1:012345678910:key/abcdef10-1517-49d8-b085-77c50b904149",
                    }
                ],
                [
                    {
                        AliasArn: "arn:aws:kms:us-east-1:012345678910:alias/example1", 
                        AliasName: "alias/example1", 
                        TargetKeyId: "abcdef10-1517-49d8-b085-77c50b904149"
                    }
                ]
            );

            rds.run(cache, {
                rds_encryption_kms_alias: 'alias/example1'
            }, callback);
        })
    })
})