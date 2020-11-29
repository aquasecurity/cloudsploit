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
    },
];

const createCache = (parameters) => {
    return {
        ssm: {
            describeParameters: {
                'us-east-1': {
                    data: parameters
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
        it('should PASS if parameter of type SecureString', function (done) {
            const cache = createCache([describeParameters[0]]);
            ssmEncryptedParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Non-SecureString parameters present', function (done) {
            const cache = createCache([describeParameters[1]]);
            ssmEncryptedParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
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