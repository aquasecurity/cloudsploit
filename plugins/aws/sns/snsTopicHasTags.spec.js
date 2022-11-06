var expect = require('chai').expect;
const snsTopicHasTags = require('./snsTopicHasTags');


const listTopics = [
    { TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic-137' },
];

const resourcegroupstaggingapi = [
    {
        "ResourceARN": "arn:aws:sns:us-east-1:111122223333:test-topic-137",
        "Tags": [{key:"key1", value:"value"}],
    },
    {
        "ResourceARN": "arn:aws:sns:us-east-1:111122223333:test-topic-137",
        "Tags": [],
    }
    
];

const createCache = (listTopics, rgData) => {
    return {
        sns: {
            listTopics: {
                'us-east-1': {
                    data: listTopics
                },
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

const createErrorCache = () => {
    return {
        sns: {
            listTopics: {
                'us-east-1': {
                    err: {
                        message: 'error while listing topics'
                    },
                },
            },
        },
    };
};

const createTopicAttributesErrorCache = (listTopics) => {
    return {
        sns: {
            listTopics: {
                'us-east-1': {
                    data: listTopics
                },
            },
        },
    };
};


describe('snsTopicHasTags', function () {
    describe('run', function () {
        it('should PASS if SNS topic has tags', function (done) {
            const cache = createCache([listTopics[0]], [resourcegroupstaggingapi[0]]);
            snsTopicHasTags.run(cache, {}, (err, results) => {
                console.log(results)
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('SNS topic has tags');
                done();
            });
        });

        it('should FAIL if SNS topic does not have tags', function (done) {
            const cache = createCache([listTopics[0]], [resourcegroupstaggingapi[1]]);
            snsTopicHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('SNS topic does not have any tags')
                done();
            });
        });

        it('should PASS if no SNS topics found', function (done) {
            const cache = createCache([]);
            snsTopicHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No SNS topics found')
                done();
            });
        });

        it('should UNKNOWN if error while listing SNS topics', function (done) {
            const cache = createCache(null, null);
            snsTopicHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for SNS topics')
                done();
            });
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const cache = createCache([listTopics[0]], null);
            snsTopicHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources')
                done();
            });
        });

    });
});