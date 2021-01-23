var expect = require('chai').expect;
var ssmEncryptedParameters = require('./ssmEncryptedParameters')

const describeParameters = [
    {
        "Name": "test-param2",
        "Type": "SecureString",
        "KeyId": "alias/aws/ssm",
        "LastModifiedDate": "1605235841.342",
        "LastModifiedUser": "arn:aws:iam::111122223333:user/cloudsploit",
        "Version": 1,
        "Tier": "Standard",
        "Policies": [],
        "DataType": "text"
    },
    {
        "Name": "test-param",
        "Type": "String",
        "LastModifiedDate": "1605235821.506",
        "LastModifiedUser": "arn:aws:iam::111122223333:user/cloudsploit",
        "Version": 1,
        "Tier": "Standard",
        "Policies": [],
        "DataType": "text"
    }
];

const listAliases = [
    {
        "AliasName": "alias/aws/ssm",
        "AliasArn": "arn:aws:kms:us-east-1:112233445566:alias/aws/ssm",
        "TargetKeyId": "0723d7e2-8655-4553-b4e3-20084f6bddba"
    },
];

const listKeys = [
    {
        "KeyId": "0723d7e2-8655-4553-b4e3-20084f6bddba",
        "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/0723d7e2-8655-4553-b4e3-20084f6bddba"
    },
    {
        "KeyId": "080891c0-b3a8-42a3-91be-c23aa7b46d3f",
        "KeyArn": "arn:aws:kms:us-east-1:112233445566:key/080891c0-b3a8-42a3-91be-c23aa7b46d3f"
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "KeyId": '0723d7e2-8655-4553-b4e3-20084f6bddba',
            "Arn": 'arn:aws:kms:us-east-1:112233445566:key/0723d7e2-8655-4553-b4e3-20084f6bddba',
            "Origin": 'AWS_KMS',
            "KeyManager": 'AWS',
        }
    }
];

const createCache = (parameters, listKeys, listAliases, describeKey) => {
    var keyId = (listKeys && listKeys.length) ? listKeys[0].KeyId : null;
    return {
        ssm: {
            describeParameters: {
                'us-east-1': {
                    data: parameters
                }
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: listKeys
                }
            },
            listAliases: {
                'us-east-1': {
                    data: listAliases
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        data: describeKey
                    }
                }
            }
        },
        sts: {
            getCallerIdentity: {
                data: '112233445566'
            }
        }
    };
};

const createErrorCache = () => {
    return {
        ssm:{
            describeParameters: {
                'us-east-1': {
                    err: {
                        message: 'error describing SSM parameters'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        ssm:{
            describeParameters: {
                'us-east-1': null,
            },
        },
    };
};

describe('ssmEncryptedParameters', function () {
    describe('run', function () {
        it('should PASS if parameter is encrypted to minimum desired encryption level', function (done) {
            const cache = createCache([describeParameters[0]], listKeys, listAliases, describeKey[0]);
            ssmEncryptedParameters.run(cache, { ssm_encryption_level: 'awskms' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if parameter is not encrypted to minimum desired encryption level', function (done) {
            const cache = createCache([describeParameters[0]], listKeys, listAliases, describeKey[0]);
            ssmEncryptedParameters.run(cache, { ssm_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Non-SecureString parameter present', function (done) {
            const cache = createCache([describeParameters[1]], listKeys, listAliases);
            ssmEncryptedParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if Non-SecureString parameter present but allowed', function (done) {
            const cache = createCache([describeParameters[1]], listKeys, listAliases);
            ssmEncryptedParameters.run(cache, { allow_ssm_non_secure_strings: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no parameters present', function (done) {
            const cache = createCache([]);
            ssmEncryptedParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for SSM parameters', function (done) {
            const cache = createErrorCache();
            ssmEncryptedParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe parameters response not found', function (done) {
            const cache = createNullCache();
            ssmEncryptedParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});