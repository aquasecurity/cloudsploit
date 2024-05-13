var expect = require('chai').expect;
const sqsHasTags = require('./sqsHasTags');

const listQueues = [
    "https://sqs.us-east-1.amazonaws.com/112233445566/test1152"
]

const getResources = [
    {
        "ResourceARN": "arn:aws:sqs:us-east-1:112233445566:test1152",
        "Tags": [],
    },
     {
        "ResourceARN": "arn:aws:sqs:us-east-1:112233445566:test1152",
        "Tags": [{key: 'value'}],
    }
]


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
    };
};

const createNullCache = () => {
    return {
        sqs: {
            listQueues: {
                'us-east-1': null,
            },
        },
    };
};


describe('sqsHasTags', function () {
    describe('run', function () {
        it('should PASS if SQS queue has tags', function (done) {
            const cache = createCache([listQueues[0]], [getResources[1]]);
            sqsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('sqs has tags')
                done();
            });
        });

        it('should FAIL if SQS queue does not have tags', function (done) {
            const cache = createCache([listQueues[0]], [getResources[0]]);
            sqsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('sqs does not have any tags')
                done();
            });
        });

        it('should PASS if no No Amazon SQS queues found', function (done) {
            const cache = createCache([]);
            sqsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Amazon SQS queues found')
                done();
            });
        });

        it('should UNKNOWN if unable to query SQS Queues', function (done) {
            const cache = createNullCache();
            sqsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Amazon SQS queues: ')
                done();
            });
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const cache = createCache([listQueues[0]],null);
            sqsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources')
                done();
            });
        });
    });
});
