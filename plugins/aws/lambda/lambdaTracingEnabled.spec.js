const expect = require('chai').expect;
var lambdaTracingEnabled = require('./lambdaTracingEnabled');

const listFunctions = [
    {
        "FunctionName": "test-lambda",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::000011112222:role/lambda-role",
        "Handler": "index.handler",
        "TracingConfig": { "Mode": "PassThrough" }
    },
    {
        "FunctionName": "testing-123",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:testing-123",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::000011112222:role/service-role/testing-123-role-7t7oo29b",
        "Handler": "index.handler",
        "TracingConfig": { "Mode": "Active" }
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

describe('lambdaTracingEnabled', function () {
    describe('run', function () {

        it('should PASS if fcuntion has active tracing', function (done) {
            const cache = createCache([listFunctions[1]]);
            lambdaTracingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if function does not have active tracing', function (done) {
            const cache = createCache([listFunctions[0]]);
            lambdaTracingEnabled.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Lambda functons found', function (done) {
            const cache = createCache([]);
            lambdaTracingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list Lambda functions', function (done) {
            const cache = createErrorCache();
            lambdaTracingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list Lambda functions response not found', function (done) {
            const cache = createNullCache();
            lambdaTracingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});