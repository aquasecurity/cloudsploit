var expect = require('chai').expect;
var dataCatalogCmkEncrypted = require('./dataCatalogCmkEncrypted');

const getDataCatalogEncryptionSettings = [
    {
        "EncryptionAtRest": {
            "CatalogEncryptionMode": "SSE-KMS",
            "SseAwsKmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/75e9285f-ae6b-4c36-9405-06e67bcc7ef1"
        },
        "ConnectionPasswordEncryption": {
            "ReturnConnectionPasswordEncrypted": false
        }
    },
    {
        "EncryptionAtRest": {
            "CatalogEncryptionMode": "DISABLED"
        },
        "ConnectionPasswordEncryption": {
            "ReturnConnectionPasswordEncrypted": false
        }
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "111122223333",
            "KeyId": "75e9285f-ae6b-4c36-9405-06e67bcc7ef1",
            "Arn": "arn:aws:kms:us-east-1:111122223333:key/75e9285f-ae6b-4c36-9405-06e67bcc7ef1",
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
            "AWSAccountId": "111122223333",
            "KeyId": "75e9285f-ae6b-4c36-9405-06e67bcc7ef1",
            "Arn": "arn:aws:kms:us-east-1:111122223333:key/75e9285f-ae6b-4c36-9405-06e67bcc7ef1",
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
]

const createCache = (configurations, describeKey, configurationsErr, describeKeyErr) => {
    var keyId = (configurations && configurations.EncryptionAtRest && configurations.EncryptionAtRest.SseAwsKmsKeyId) ? configurations.EncryptionAtRest.SseAwsKmsKeyId.split('/')[1] : null;
    return {
        glue: {
            getDataCatalogEncryptionSettings: {
                'us-east-1': {
                    err: configurationsErr,
                    data: configurations
                },
            },
        },
        kms: {
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

const createNullCache = () => {
    return {
        glue: {
            getDataCatalogEncryptionSettings: {
                'us-east-1': null
            }
        },
        kms: {
            describeKey: {
                'us-east-1': null
            }
        },
    };
};

describe('dataCatalogCmkEncrypted', function () {
    describe('run', function () {
        it('should PASS if Glue data catalog has encryption at-rest enabled for metadata using Customer Master Key', function (done) {
            const cache = createCache(getDataCatalogEncryptionSettings[0], describeKey[0]);
            dataCatalogCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Glue data catalog has encryption at-rest enabled for metadata using AWS-managed key', function (done) {
            const cache = createCache(getDataCatalogEncryptionSettings[0], describeKey[1]);
            dataCatalogCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Glue data catalog does not have encryption at-rest enabled for metadata', function (done) {
            const cache = createCache(getDataCatalogEncryptionSettings[1]);
            dataCatalogCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to get AWS Glue data catalog encryption settings', function (done) {
            const cache = createCache(null, null, { message: "Unable to get AWS Glue data catalog encryption settings" });
            dataCatalogCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe KMS key', function (done) {
            const cache = createCache(getDataCatalogEncryptionSettings[0], describeKey[0], null, { message: "Unable to describe KMS key" });
            dataCatalogCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get datalog encryption settings response not found', function (done) {
            const cache = createNullCache();
            dataCatalogCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
}); 