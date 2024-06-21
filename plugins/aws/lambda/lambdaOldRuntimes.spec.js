const expect = require('chai').expect;
var lambdaOldRuntimes = require('./lambdaOldRuntimes');

const listFunctions = [
    {
        "FunctionName": "test-lambda",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda",
        "Runtime": "nodejs16.x",
        "Role": "arn:aws:iam::000011112222:role/lambda-role",
        "Handler": "index.handler",
        "TracingConfig": { "Mode": "PassThrough" }
    },
    {
        "FunctionName": "testing-123",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:testing-123",
        "Runtime": "nodejs4.3",
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

describe('lambdaOldRuntimes', function () {
    describe('run', function () {

        it('should PASS if functions is using current version', function (done) {
            const cache = createCache([listFunctions[0]]);
            lambdaOldRuntimes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Lambda is running the current version');
                done();
            });
        });

        it('should FAIL if function is using out-of-date runtime', function (done) {
            const cache = createCache([listFunctions[1]]);
            lambdaOldRuntimes.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('which was deprecated on');
                done();
            });
        });

        it('should PASS if no Lambda functons found', function (done) {
            const cache = createCache([]);
            lambdaOldRuntimes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Lambda functions found');
                done();
            });
        });

        it('should UNKNOWN if unable to list Lambda functions', function (done) {
            const cache = createErrorCache();
            lambdaOldRuntimes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Lambda functions');
                done();
            });
        });

        it('should not return anything if list Lambda functions response not found', function (done) {
            const cache = createNullCache();
            lambdaOldRuntimes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
