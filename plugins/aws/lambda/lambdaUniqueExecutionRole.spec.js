var expect = require('chai').expect;
var lambda = require('./lambdaUniqueExecutionRole');

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
        "Runtime": "nodejs4.3",
        "Role": "arn:aws:iam::000011112222:role/lambda-role",
        "Handler": "index.handler",
        "TracingConfig": { "Mode": "Active" }
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

const createCache = (lambdaData) => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: null,
                    data: lambdaData
                }
            }
        },
    }
};

describe('lambdaHasTags', function () {
    describe('run', function () {
        it('should give unknown result if unable to list the lambda functions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Lambda functions');
                done();
            };

            const cache = createCache(null, []);
            lambda.run(cache, {}, callback);
        });

        it('should give passing result if no lambda function found in region', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Lambda functions found');
                done();
            };

            const cache = createCache([], null);
            lambda.run(cache, {}, callback);
        });

        it('should give passing result if Lambda function have unique execution role', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Lambda function have unique execution role');
                done();
            };
            const cache = createCache([listFunctions[0], listFunctions[2]]);
            lambda.run(cache, {}, callback);
        })

        it('should give failing result if lambda function does not have unique execution role', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('Lambda function does not have unique execution role');
                done();
            };
            const cache = createCache([listFunctions[0], listFunctions[1]]);
            lambda.run(cache, {}, callback);
        });

    });
});
