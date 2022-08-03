var expect = require('chai').expect;
var timestreamDatabaseEncrypted = require('./timestreamDatabaseEncrypted');

const listDatabases = [
        {
            "Arn": "arn:aws:timestream:us-east-1:000011112222:database/akhtar-db1",
            "DatabaseName": "akhtar-db1",
            "TableCount": 0,
            "KmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/b6d7913b-5604-47c5-8291-8270a1abab58",
            "CreationTime": "2021-11-12T03:27:12.190000-08:00",
            "LastUpdatedTime": "2021-11-12T03:27:12.190000-08:00"
        },
        {
            "Arn": "arn:aws:timestream:us-east-1:000011112222:database/sampleDB",
            "DatabaseName": "sampleDB",
            "TableCount": 0,
            "KmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "CreationTime": "2021-11-12T02:59:33.357000-08:00",
            "LastUpdatedTime": "2021-11-12T02:59:33.357000-08:00"
        }
];

const listKeys = [
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
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
            "KeyId": "2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/b6d7913b-5604-47c5-8291-8270a1abab58",
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

const createCache = (databases, keys, describeKey, databasesErr, keysErr, describeKeyErr) => {
    var keyId = (databases && databases.length && databases[0].KmsKeyId) ? databases[0].KmsKeyId.split('/')[1] : null;
    return {
        timestreamwrite: {
            listDatabases: {
                'us-east-1': {
                    err: databasesErr,
                    data: databases
                },
            },
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


describe('timestreamDatabaseEncrypted', function () {
    describe('run', function () {
        it('should PASS if Timestream database is encrypted with desired encryption level', function (done) {
            const cache = createCache([listDatabases[1]], listKeys, describeKey[0]);
            timestreamDatabaseEncrypted.run(cache, { timestream_databases_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Timestream database is encrypted with awscmk');
                done();
            });
        });


        it('should FAIL if Timestream database is not encrypted with desired encyption level', function (done) {
            const cache = createCache([listDatabases[0]], listKeys, describeKey[1]);
            timestreamDatabaseEncrypted.run(cache, { timestream_databases_desired_encryption_level:'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Timestream database is encrypted with awskms');
                done();
            });
        });

        it('should PASS if no Timestream Databases found', function (done) {
            const cache = createCache([]);
            timestreamDatabaseEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Timestream databases found');
                done();
            });
        });

        it('should UNKNOWN if unable to list Timestream databases', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Timestream databases encryption" });
            timestreamDatabaseEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list KMS keys" });
            timestreamDatabaseEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
