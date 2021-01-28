const expect = require('chai').expect;
var envVarsClientSideEncryption = require('./envVarsClientSideEncryption');

const listFunctions = [
    {
        "FunctionName": "test-lambda",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::000011112222:role/lambda-role",
        "Handler": "index.handler",
        "Environment": {
            "Variables": {
                "password": "AQICAHgYvhTIHqe+Awrx6K5feBosORFD4FbhQ/XEyM9ERVB+yAF+yJdS1QYRvl9adezS+RnyAAAAaDBmBgkqhkiG9w0BBwagWTBXAgEAMFIGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMw+VYDIrQVRJZeqO7AgEQgCWCe+TPNAr1VjxRifoBTXwu0YPZZJKLC7yMvnbpC7IqPQemWlTD",
                "key": "AQICAHgYvhTIHqe+Awrx6K5feBosORFD4FbhQ/XEyM9ERVB+yAF6IL+r1bQLUR/zYcJYODM2AAAAZzBlBgkqhkiG9w0BBwagWDBWAgEAMFEGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM5aerBTI5DqTnEsVWAgEQgCR72Vdqcvzq/k5fON7IfxDMEEh4FAfcxhq0FKyvJXi8Pc0B7ds="
            }
        }
    },
    {
        "FunctionName": "testing-123",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:testing-123",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::000011112222:role/service-role/testing-123-role-7t7oo29b",
        "Handler": "index.handler",
        "Environment": {
            "Variables": {
                "password": "fastabc123",
            }
        }
    },
    {
        "FunctionName": "testing-124",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:testing-124",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::000011112222:role/service-role/testing-123-role-7t7oo29b",
        "Handler": "index.handler"
    }
];


const createCache = (listFunctions) => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    data: listFunctions
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: {
                        message: 'error listing Lambda functions'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': null
            }
        }
    };
};

describe('envVarsClientSideEncryption', function () {
    describe('run', function () {

        it('should PASS if sensitive environment variable values are encrypted', function (done) {
            const cache = createCache([listFunctions[0]]);
            envVarsClientSideEncryption.run(cache, { lambda_sensitive_env_vars: 'password,key' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if sensitive environment variable values are not encrypted', function (done) {
            const cache = createCache([listFunctions[1]]);
            envVarsClientSideEncryption.run(cache, { lambda_sensitive_env_vars: 'password' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Lambda functons found', function (done) {
            const cache = createCache([]);
            envVarsClientSideEncryption.run(cache, { lambda_sensitive_env_vars: 'password,key' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no environment variable found', function (done) {
            const cache = createCache([listFunctions[2]]);
            envVarsClientSideEncryption.run(cache, { lambda_sensitive_env_vars: 'password,key' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no sensitive environment variable found', function (done) {
            const cache = createCache([listFunctions[0]]);
            envVarsClientSideEncryption.run(cache, { lambda_sensitive_env_vars: 'access_keys' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list Lambda functions', function (done) {
            const cache = createErrorCache();
            envVarsClientSideEncryption.run(cache, { lambda_sensitive_env_vars: 'password,key' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list Lambda functions response not found', function (done) {
            const cache = createNullCache();
            envVarsClientSideEncryption.run(cache, { lambda_sensitive_env_vars: 'password,key' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should not return anything if settings for senstibe lambda enironment variable not given', function (done) {
            const cache = createNullCache();
            envVarsClientSideEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});