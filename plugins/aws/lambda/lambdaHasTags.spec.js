var expect = require('chai').expect;
var lambda = require('./lambdaHasTags');

const createCache = (lambdaData, rgData) => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: null,
                    data: lambdaData
                }
            }
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        }
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

            const cache = createCache(
                null, []
            );

            lambda.run(cache, {}, callback);
        });

        it('should give passing result if no lambda function found in region', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Lambda functions found');
                done();
            };

            const cache = createCache(
                [], null
            );

            lambda.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query all resources from group');
                done();
            };

            const cache = createCache(
                [{
                    "FunctionName": "mb-ngsc-test",
                    "FunctionArn": "arn:aws:lambda:us-east-1:666",
                }],
                null
            );

            lambda.run(cache, {}, callback);
        });

        it('should give passing result if lambda function has tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Lambda function has tags');
                done();
            };

            const cache = createCache(
                [{
                    "FunctionName": "mb-ngsc-test",
                    "FunctionArn": "arn:aws:lambda:us-east-1:666",
                }],
                [{
                    "ResourceARN": "arn:aws:lambda:us-east-1:666",
                    "Tags": [{key:"key1", value:"value"}],
                }]
            );
            lambda.run(cache, {}, callback);
        })

        it('should give failing result if lambda function does not have tags', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(2);
                    expect(results[0].message).to.include('Lambda function does not have any tags');
                    done();
                };

               const cache = createCache(
                [{
                    "FunctionName": "mb-ngsc-test",
                    "FunctionArn": "arn:aws:lambda:us-east-1:666",
                }],
                [{
                    "ResourceARN": "arn:aws:lambda:us-east-1:666",
                    "Tags": [],
                }]
            );

            lambda.run(cache, {}, callback);
        });

    });
});
