var assert = require('assert');
var expect = require('chai').expect;
var lambda = require('./lambdaLogGroups');

const createCache = (lambdaData, cwData) => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: null,
                    data: lambdaData
                }
            }
        },
        cloudwatchlogs: {
            describeLogGroups: {
                'us-east-1': {
                    err: null,
                    data: cwData
                }
            }
        }
    }
};

describe('lambdaLogGroups', function () {
    describe('run', function () {
        it('should give passing result if no Lambda functions are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No Lambda functions found')
                done()
            };

            const cache = createCache(
                [], []
            );

            lambda.run(cache, {}, callback);
        })

        it('should give failing result if no log groups are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Error querying for log groups')
                done()
            };

            const cache = createCache(
                [{
                    "FunctionName": "mb-ngsc-test",
                    "FunctionArn": "arn:aws:lambda:us-east-1:555",
                }], null
            );

            lambda.run(cache, {}, callback);
        })

        it('should give passing result if log group name matches with function name', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Function has log group:')
                done()
            };

            const cache = createCache(
                [{
                    "FunctionName": "mb-ngsc-test",
                    "FunctionArn": "arn:aws:lambda:us-east-1:666",
                }],
                [{
                    "logGroupName": "/aws/lambda/mb-ngsc-test",
                    "arn": "arn:aws:lambda:us-east-1:555",
                }]
            );

            lambda.run(cache, {}, callback);
        })

        it('should give failing result if no log group names match with the function', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Function has no log group')
                done()
            };

            const cache = createCache(
                [{
                    "FunctionName": "mb-ngsc-test",
                    "FunctionArn": "arn:aws:lambda:us-east-1:666",
                }],
                [{
                    "logGroupName": "/aws/lambda/test",
                    "arn": "arn:aws:logs:us-east-1:555",
                }]
            );
            lambda.run(cache, {}, callback);
        })

        it('should give a passing result if a log group names match with the function@edge in the same region', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    expect(results[0].message).to.include('/aws/lambda/us-east-1.fp-ngsc-test')
                    done()
                };

                const cache = createCache(
                    [{
                        "FunctionName": "fp-ngsc-test",
                        "FunctionArn": "arn:aws:lambda:us-east-1:666",
                    }],
                    [{
                        "logGroupName": "/aws/lambda/us-east-1.fp-ngsc-test",
                        "arn": "arn:aws:logs:us-east-1:555",
                    }]
                );

            lambda.run(cache, {}, callback);
        })

        it('should give a passing result if a log group names match with the function@edge in a different region', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('/aws/lambda/us-east-1.fp-ngsc-test')
                done()
            };

            const customCache = (lambdaData, cwData) => {
                return {
                    lambda: {
                        listFunctions: {
                            'us-east-1': {
                                err: null,
                                data: lambdaData
                            }
                        }
                    },
                    cloudwatchlogs: {
                        describeLogGroups: {
                            'us-east-1':{
                                err: null,
                                data:[]
                            },
                            'us-east-2': {
                                err: null,
                                data: cwData
                            }
                        }
                    }
                }
            };

            const cache = customCache(
                [{
                    "FunctionName": "fp-ngsc-test",
                    "FunctionArn": "arn:aws:lambda:us-east-1:666",
                }],
                [{
                    "logGroupName": "/aws/lambda/us-east-1.fp-ngsc-test",
                    "arn": "arn:aws:logs:us-east-1:555",
                }]
            );

            lambda.run(cache, {}, callback);
        })

        it('should give a failing result if a log group names matches with the function name without the region', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('unction has no log group')
                done()
            };

            const customCache = (lambdaData, cwData) => {
                return {
                    lambda: {
                        listFunctions: {
                            'us-east-1': {
                                err: null,
                                data: lambdaData
                            }
                        }
                    },
                    cloudwatchlogs: {
                        describeLogGroups: {
                            'us-east-1':{
                                err: null,
                                data:[]
                            },
                            'us-east-2': {
                                err: null,
                                data: cwData
                            }
                        }
                    }
                }
            };

            const cache = customCache(
                [{
                    "FunctionName": "fp-ngsc-test",
                    "FunctionArn": "arn:aws:lambda:us-east-1:666",
                }],
                [{
                    "logGroupName": "/aws/lambda/fp-ngsc-test",
                    "arn": "arn:aws:logs:us-east-1:555",
                }]
            );

            lambda.run(cache, {}, callback);
        })
    })
})
