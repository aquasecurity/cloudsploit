var expect = require('chai').expect;
var finspaceEnvironmentEncrypted = require('./finspaceEnvironmentEncrypted');

const listEnvironments = [
    {
        "name": "sadeed1",
        "environmentId": "yk7kg7l6ab3yr42gse4jv3",
        "awsAccountId": "000011112222",
        "status": "CREATED",
        "environmentUrl": "yk7kg7l6ab3yr42gse4jv3.us-east-1.amazonfinspace.com",
        "environmentArn": "arn:aws:finspace:us-east-1:000011112222:environment/yk7kg7l6ab3yr42gse4jv3",
        "sageMakerStudioDomainUrl": "https://d-7mzarbqaxxay.studio.us-east-1.sagemaker.aws",
        "kmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "dedicatedServiceAccountId": "000011112222",
        "federationMode": "LOCAL",
        "federationParameters": {}
    }
];

const listKeys = [
    {
        "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
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
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
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

const createCache = (environments, keys, describeKey, environmentsErr, keysErr, describeKeyErr) => {
    var keyId = (environments && environments.length && environments[0].kmsKeyId) ? environments[0].kmsKeyId.split('/')[1] : null;
    return {
        finspace: {
            listEnvironments: {
                'us-east-1': {
                    err: environmentsErr,
                    data: environments
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




describe('finspaceEnvironmentEncrypted', function () {
    describe('run', function () {
        it('should PASS if FinSpace Environment is encrypted with desired encryption level', function (done) {
            const cache = createCache([listEnvironments[0]], listKeys, describeKey[0]);
            finspaceEnvironmentEncrypted.run(cache, { finspace_environment_encryption: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('FinSpace environment is encrypted with awscmk');
                done();
            });
        });

        it('should FAIL if FinSpace Environment is not encrypted with desired encyption level', function (done) {
            const cache = createCache([listEnvironments[0]], listKeys, describeKey[1]);
            finspaceEnvironmentEncrypted.run(cache, { finspace_environment_encryption: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('FinSpace environment is encrypted with awskms');
                done();
            });
        });

        it('should PASS if no FinSpace Environment found', function (done) {
            const cache = createCache([]);
            finspaceEnvironmentEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No FinSpace Environment  found');
                done();
            });
        });

        it('should UNKNOWN if unable to list FinSpace Environment', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list FinSpace Environment encryption" });
            finspaceEnvironmentEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list KMS keys" });
            finspaceEnvironmentEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});