var expect = require('chai').expect;
var s3EncryptionMode = require('./glueS3EncryptionEnabled');

const getSecurityConfigurations = [
    {
        "Name": "config-test",
        "CreatedTimeStamp": "2020-12-15T03:32:22.300000+05:00",
        "EncryptionConfiguration": {
            "S3Encryption": [
                {
                    "S3EncryptionMode": "SSE-KMS",
                    "KmsKeyArn": "arn:aws:kms:us-east-1:111122223333:key/7cb78370-cdc6-4ccb-a973-ecc8cbdc0dec"
                }
            ],
            "CloudWatchEncryption": {
                "CloudWatchEncryptionMode": "DISABLED"
            },
            "JobBookmarksEncryption": {
                "JobBookmarksEncryptionMode": "DISABLED"
            }
        }
    },
    {
        "Name": "config-test2",
        "CreatedTimeStamp": "2020-12-15T02:20:28.329000+05:00",
        "EncryptionConfiguration": {
            "S3Encryption": [
                {
                    "S3EncryptionMode": "DISABLED"
                }
            ],
            "CloudWatchEncryption": {
                "CloudWatchEncryptionMode": "DISABLED"
            },
            "JobBookmarksEncryption": {
                "JobBookmarksEncryptionMode": "DISABLED"
            }
        }
    }
];

const listKeys = [
    {
        "KeyId": "7cb78370-cdc6-4ccb-a973-ecc8cbdc0dec",
        "KeyArn": "arn:aws:kms:us-east-1:111122223333:key/7cb78370-cdc6-4ccb-a973-ecc8cbdc0dec"
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "111122223333",
            "KeyId": "7cb78370-cdc6-4ccb-a973-ecc8cbdc0dec",
            "Arn": "arn:aws:kms:us-east-1:111122223333:key/7cb78370-cdc6-4ccb-a973-ecc8cbdc0dec",
            "CreationDate": 1598523566.709,
            "Enabled": true,
            "Description": "Default master key that protects my S3 objects when no other key is defined",
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

const createCache = (configurations, listKeys, describeKey) => {
    var keyId = (listKeys && listKeys.length) ? listKeys[0].KeyId : null;
    return {
        glue: {
            getSecurityConfigurations: {
                'us-east-1': {
                    data: configurations
                },
            },
        },
        kms: {
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
    };
};

const createErrorCache = () => {
    return {
        glue: {
            getSecurityConfigurations: {
                'us-east-1': {
                    err: {
                        message: 'error getting AWS Glue security configurations'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        glue: {
            getSecurityConfigurations: {
                'us-east-1': null
            }
        },
    };
};

describe('s3EncryptionMode', function () {
    describe('run', function () {
        it('should PASS if AWS Glue security configuration has s3 encryption enabled', function (done) {
            const cache = createCache([getSecurityConfigurations[0]], listKeys, describeKey[0]);
            s3EncryptionMode.run(cache, { glue_s3_encryption_level: 'awskms' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if AWS Glue security configuration does not hsve s3 encryption enabled at desired level', function (done) {
            const cache = createCache([getSecurityConfigurations[0]], listKeys, describeKey[0]);
            s3EncryptionMode.run(cache, { glue_s3_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if AWS Glue security configuration does not have s3 encryption disabled', function (done) {
            const cache = createCache([getSecurityConfigurations[1]]);
            s3EncryptionMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No AWS Glue security configurations found', function (done) {
            const cache = createCache([]);
            s3EncryptionMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to get AWS Glue security configurations', function (done) {
            const cache = createErrorCache();
            s3EncryptionMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get security configurations response not found', function (done) {
            const cache = createNullCache();
            s3EncryptionMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
}); 