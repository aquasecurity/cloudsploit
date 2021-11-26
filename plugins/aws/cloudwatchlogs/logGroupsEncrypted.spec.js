var expect = require('chai').expect;
var logGroupsEncrypted = require('./logGroupsEncrypted');


const describeLogGroups = [
    {
        logGroupName: 'akhtar-lg',
        creationTime: 1636375012619,
        metricFilterCount: 0,
        arn: 'arn:aws:logs:us-east-1:000011112222:log-group:akhtar-lg:*',
        storedBytes: 0,
        kmsKeyId: 'arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250'
    },
    {
        logGroupName: 'test-lg-1',
        creationTime: 1607077091876,
        retentionInDays: 3,
        metricFilterCount: 0,
        arn: 'arn:aws:logs:us-east-1:000011112222:log-group:test-lg-1:*',
        storedBytes: 0
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

const createCache = (logGroups, keys, describeKey, logGroupErr, keysErr, describeKeyErr) => {
    var keyId = (logGroups && logGroups.length && logGroups[0].kmsKeyId) ? logGroups[0].kmsKeyId.split('/')[1] : null;
    return {
        cloudwatchlogs: {
            describeLogGroups: {
                'us-east-1': {
                    err: logGroupErr,
                    data: logGroups
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




describe('logGroupsEncrypted', function () {
    describe('run', function () {
        it('should PASS if CloudWatch Logs log group is encrypted with desired encryption level', function (done) {
            const cache = createCache([describeLogGroups[0]], listKeys, describeKey[0]);
            logGroupsEncrypted.run(cache, {cloudwatchlog_groups_desired_encryption_level :'awscmk'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('CloudWatch log group is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should FAIL if CloudWatch Logs log groups is not encrypted with desired encyption level', function (done) {
            const cache = createCache([describeLogGroups[1]], listKeys, describeKey[1]);
            logGroupsEncrypted.run(cache, { cloudwatchlog_groups_desired_encryption_level:'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('CloudWatch log group is encrypted with awskms');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should PASS if no CloudWatch Logs log groups  found', function (done) {
            const cache = createCache([]);
            logGroupsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No CloudWatch log groups found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list CloudWatch Logs log groups', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list CloudWatch Logs log groups encryption" });
            logGroupsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list KMS keys" });
            logGroupsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});  