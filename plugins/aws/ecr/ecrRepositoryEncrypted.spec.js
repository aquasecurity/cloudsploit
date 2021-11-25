var expect = require('chai').expect;
var ecrRepositoryEncrypted = require('./ecrRepositoryEncrypted');

const describeRepositories = [
    {
        "repositoryArn": "arn:aws:ecr:us-east-1:000011112222:repository/private-test",
        "registryId": "560213429563",
        "repositoryName": "private-test",
        "repositoryUri": "000011112222.dkr.ecr.us-east-1.amazonaws.com/private-test",
        "createdAt": "2021-07-24T17:20:58+05:00",
        "imageTagMutability": "MUTABLE",
        "imageScanningConfiguration": {
            "scanOnPush": false
        },
        "encryptionConfiguration": {
            "encryptionType": "AES256"
        }
    },
    {
        "repositoryArn": "arn:aws:ecr:us-east-1:000011112222:repository/sad",
        "registryId": "560213429563",
        "repositoryName": "sad",
        "repositoryUri": "560213429563.dkr.ecr.us-east-1.amazonaws.com/sad",
        "createdAt": "2021-11-12T21:35:40+05:00",
        "imageTagMutability": "MUTABLE",
        "imageScanningConfiguration": {
            "scanOnPush": false
        },
        "encryptionConfiguration": {
            "encryptionType": "KMS",
            "kmsKey": "arn:aws:kms:us-east-1:000011112222:key/92e3e4cf-dfc3-4ea7-a225-22542c8e1528"
        }
    },
    {
        "repositoryArn": "arn:aws:ecr:us-east-1:000011112222:repository/sadeed1",
        "registryId": "560213429563",
        "repositoryName": "sadeed1",
        "repositoryUri": "000011112222.dkr.ecr.us-east-1.amazonaws.com/sadeed1",
        "createdAt": "2021-11-12T19:56:56+05:00",
        "imageTagMutability": "MUTABLE",
        "imageScanningConfiguration": {
            "scanOnPush": false
        },
        "encryptionConfiguration": {
            "encryptionType": "KMS",
            "kmsKey": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
        }
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

const createCache = (repository, keys, describeKey, repositoryErr, keysErr, describeKeyErr) => {
    var keyId = (repository && repository.length && repository[0].encryptionConfiguration.kmsKey) ? repository[0].encryptionConfiguration.kmsKey.split('/')[1] : null;
    return {
        ecr: {
            describeRepositories: {
                'us-east-1': {
                    err: repositoryErr,
                    data: repository
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



describe('ecrRepositoryEncrypted', function () {
    describe('run', function () {
        it('should PASS if ECR Repository is encrypted with desired encryption level', function (done) {
            const cache = createCache([describeRepositories[2]], listKeys, describeKey[0]);
            ecrRepositoryEncrypted.run(cache, { ecr_repository_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('ECR repository is encrypted with awscmk');
                done();
            });
        });

        it('should FAIL if ECR Repository is not encrypted with desired encyption level', function (done) {
            const cache = createCache([describeRepositories[1]], listKeys, describeKey[1]);
            ecrRepositoryEncrypted.run(cache, { ecr_repository_desired_encryption_level:'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('ECR repository encrypted with awskms');
                done();
            });
        });

        it('should PASS if no ECR Repository found', function (done) {
            const cache = createCache([]);
            ecrRepositoryEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ECR repositories found');
                done();
            });
        });

        it('should UNKNOWN if unable to list ECR Repository', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list ECR repositories" });
            ecrRepositoryEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list ECR repositories');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list KMS keys" });
            ecrRepositoryEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
