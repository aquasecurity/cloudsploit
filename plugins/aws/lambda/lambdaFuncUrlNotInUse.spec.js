var expect = require('chai').expect;
var lambdaFunctionURLNotInUse = require('./lambdaFuncUrlNotInUse');

const createCache = (lambdaData, functionUrlConfigs) => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: null,
                    data: lambdaData
                }
            },
            listFunctionUrlConfigs: functionUrlConfigs
        }
    };
};

describe('Lambda Function URL Not in Use', function () {
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

            lambdaFunctionURLNotInUse.run(cache, {}, callback);
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

            lambdaFunctionURLNotInUse.run(cache, {}, callback);
        });

        it('should return passing result if lambda function URL is not configured', function (done) {
            const lambdaData = [
                {
                    "FunctionName": "test-lambda",
                    "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda"
                }
            ];

            const functionUrlConfigs = {
                'us-east-1': {
                    'test-lambda': {
                        'err': null,
                        'data': {
                            'FunctionUrlConfigs': []
                        }
                    }
                }
            };

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Lambda function Url is not configured');
                done();
            };

            const cache = createCache(lambdaData, functionUrlConfigs);

            lambdaFunctionURLNotInUse.run(cache, {}, callback);
        });

        it('should return failing result if lambda function URL is configured', function (done) {
            const lambdaData = [
                {
                    "FunctionName": "test-lambda",
                    "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda"
                }
            ];

            const functionUrlConfigs = {
                'us-east-1': {
                    'test-lambda': {
                        'err': null,
                        'data': {
                            'FunctionUrlConfigs': [{
                                FunctionUrl: "https://tetsuewfebwfweffesvvs.lambda-url.us-east-1.on.aws/",
                            }]
                        }
                    }
                }
            };

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Lambda function Url is configured');
                done();
            };

            const cache = createCache(lambdaData, functionUrlConfigs);

            lambdaFunctionURLNotInUse.run(cache, {}, callback);
        });

        it('should return unknown result if unable to list the lambda function url config', function (done) {
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
                expect(results[0].message).to.include('Unable to query for Lambda function URL configs: Unable to obtain data');
                done();
            };

            const cache = createCache(lambdaData, null);

            lambdaFunctionURLNotInUse.run(cache, {}, callback);
        });
    });
});
