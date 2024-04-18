var expect = require('chai').expect;
var lambdaDeadLetterQueue = require('./lambdaDeadLetterQueue');

const createCache = (lambdaData, functionConfigData) => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: null,
                    data: lambdaData
                }
            },
            getFunctionConfiguration: functionConfigData
        }
    };
};

describe('Lambda Dead Letter Queue', function () {
    describe('run', function () {
        it('should return unknown result if unable to list the lambda functions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Lambda functions');
                done();
            };

            const cache = createCache(null, {});

            lambdaDeadLetterQueue.run(cache, {}, callback);
        });

        it('should return unknown result if unable to list the lambda function config', function (done) {
            const lambdaData = [
                {
                    "FunctionName": "test-lambda",
                    "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda"
                }
            ];
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Lambda function config');
                done();
            };

            const cache = createCache(lambdaData, {});

            lambdaDeadLetterQueue.run(cache, {}, callback);
        });

        it('should return passing result if no lambda function found in region', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Lambda functions found');
                done();
            };

            const cache = createCache([], {});

            lambdaDeadLetterQueue.run(cache, {}, callback);
        });

        it('should return passing result if lambda function has Dead Letter Queue configured', function (done) {
            const lambdaData = [
                {
                    "FunctionName": "test-lambda",
                    "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda"
                }
            ];

            const functionConfigData = {
                "us-east-1": {
                    "test-lambda": {
                        "err": null,
                        "data": {
                            "DeadLetterConfig": {
                                "TargetArn": "arn:aws:sqs:us-east-1:000011112222:test-queue"
                            }
                        }
                    }
                }
            };

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Lambda function has dead letter queue configured');
                done();
            };

            const cache = createCache(lambdaData, functionConfigData);

            lambdaDeadLetterQueue.run(cache, {}, callback);
        });

        it('should return failing result if lambda function does not have Dead Letter Queue configured', function (done) {
            const lambdaData = [
                {
                    "FunctionName": "test-lambda",
                    "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda"
                }
            ];

            const functionConfigData = {
                "us-east-1": {
                    "test-lambda": {
                        "err": null,
                        "data": {} 
                    }
                }
            };

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Lambda function does not have dead letter queue configured');
                done();
            };

            const cache = createCache(lambdaData, functionConfigData);

            lambdaDeadLetterQueue.run(cache, {}, callback);
        });
    });
});
