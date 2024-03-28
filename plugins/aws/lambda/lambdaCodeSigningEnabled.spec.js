const expect = require('chai').expect;
const lambdaCodeSigningEnabled = require('./lambdaCodeSigningEnabled');

const listFunctions = [
    {
        "FunctionName": "test-lambda",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda",
    }
];

const codeSigningEnabledResponse = {
    "CodeSigningConfigArn": "arn:aws:lambda:us-east-1:000011112222:function-code-signing-config:test-lambda"
};

const codeSigningDisabledResponse = {};

const createCache = (listFunctions, codeSigningConfig) => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    data: listFunctions
                }
            },
            getFunctionCodeSigningConfig: {
                'us-east-1': {
                    'test-lambda': {
                        data: codeSigningConfig
                    }
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
                        message: 'Error listing Lambda functions'
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
                'us-east-1': {
                    data:{ }
                }
            }
        }
    };
};

describe('lambdaCodeSigningEnabled', function () {
    describe('run', function () {

        it('should PASS if code signing is enabled for Lambda function', function (done) {
            const cache = createCache(listFunctions, codeSigningEnabledResponse);
            lambdaCodeSigningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if code signing is not enabled for Lambda function', function (done) {
            const cache = createCache(listFunctions, codeSigningDisabledResponse);
            lambdaCodeSigningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to list Lambda functions', function (done) {
            const cache = createErrorCache();
            lambdaCodeSigningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        it('should UNKNOWN if unable to list Lambda functions code signing config', function (done) {
            const cache = createCache(listFunctions, null);
            lambdaCodeSigningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if no Lambda functions found', function (done) {
            const cache = createNullCache();
            lambdaCodeSigningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
