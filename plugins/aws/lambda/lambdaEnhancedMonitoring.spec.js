var expect = require('chai').expect;
var lambdaEnableEnhancedMonitoring = require('./lambdaEnhancedMonitoring');

const createCache = (lambdaData,functionInfoData) => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: null,
                    data: lambdaData
                }
            },
            getFunction: functionInfoData

        }
    };
};

describe('Lambda Enable Enhanced Monitoring', function () {
    describe('run', function () {
        it('should return unknown result if unable to list the lambda functions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Lambda functions');
                done();
            };

            const cache = createCache(null);

            lambdaEnableEnhancedMonitoring.run(cache, {}, callback);
        });

        it('should return passing result if no lambda function found in region', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Lambda functions found');
                done();
            };

            const cache = createCache([]);

            lambdaEnableEnhancedMonitoring.run(cache, {}, callback);
        });

        it('should return passing result if lambda function has enhanced monitoring enabled', function (done) {
            const lambdaData = [
                {
                    "FunctionName": "test-lambda",
                    "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda"
                }
            ];

            const functionInfoData = {
                "us-east-1": {
                    "test-lambda": {
                        "err": null,
                        "data": {
                            "Configuration": {
                                "Layers": [
                                    {
                                        "Arn": "arn:aws:lambda:us-east-1:000011112222:layer:LambdaInsightsExtension:1"
                                    }
                                ]
                            }
                        }
                    }
                }
            };

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Lambda functions has enhanced monitoring enabled');
                done();
            };

            const cache = createCache(lambdaData,functionInfoData);

            lambdaEnableEnhancedMonitoring.run(cache, {}, callback);
        });

        it('should return failing result if lambda function does not have enhanced monitoring enabled', function (done) {
            const lambdaData = [
                {
                    "FunctionName": "test-lambda",
                    "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda"
                }
            ];

            const functionInfoData = {
                "us-east-1": {
                    "test-lambda": {
                        "err": null,
                        "data": {
                            "Configuration": {
                                "FunctionName": "test-lambda",
                                "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda"                
                            }
                        }
                    }
                }
            };

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Lambda function does not have enhanced monitoring enabled');
                done();
            };

            const cache = createCache(lambdaData,functionInfoData);

            lambdaEnableEnhancedMonitoring.run(cache, {}, callback);
        });
    });
});
