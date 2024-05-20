var expect = require('chai').expect;
var sqsHasTags = require('./sqsHasTags');

const createCache = (listQueues, rgData) => {
    return {
        sqs: {
            listQueues: {
                'us-east-1': {
                    err: null,
                    data: listQueues
                }
            },
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '111122223333'
                }
            }
        }
    };
};

describe('SQS Has Tags', function () {
    describe('run', function () {
        it('should PASS if SQS queues have tags', function (done) {
            const cache = createCache(['https://sqs.us-east-1.amazonaws.com/111122223333/test-queue-1'], [
                {
                    "ResourceARN": "arn:aws:sqs:us-east-1:111122223333:test-queue-1",
                    "Tags": [{ key: 'name', value: 'test-queue-1' }],
                }
            ]);
            sqsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('SQS queue has tags');
                done();
            });
        });

        it('should FAIL if SQS queues do not have tags', function (done) {
            const cache = createCache(['https://sqs.us-east-1.amazonaws.com/111122223333/test-queue-1'], [
                {
                    "ResourceARN": "arn:aws:sqs:us-east-1:111122223333:test-queue-1",
                    "Tags": [],
                }
            ]);
            sqsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('SQS queue does not have any tags');
                done();
            });
        });

        it('should PASS if no SQS queues found', function (done) {
            const cache = createCache([], null);
            sqsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No SQS queues found');
                done();
            });
        });

        it('should UNKNOWN if unable to query SQS queues', function (done) {
            const cache = createCache(null, null);
            sqsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for SQS queues');
                done();
            });
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const cache = createCache(['https://sqs.us-east-1.amazonaws.com/111122223333/test-queue-1'], null);
            sqsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources');
                done();
            });
        });
    });
});
