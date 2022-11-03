var expect = require('chai').expect;
const snsTopicHasTags = require('./snsTopicHasTags');


const listTopics = [
    { TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic-137' },
    { TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic-137-2' }
];

const listTagsForResource = [
    {
    ResponseMetadata: { RequestId: '88bc2d3a-ecdf-533e-8dc3-76e62a2cABCD' },
    Tags: []
    },
    {
    ResponseMetadata: { RequestId: '88bc2d3a-ecdf-533e-8dc3-76e62a2cABCD' },
    Tags: [{key: 'value'}]
    },
    
];

const createCache = (listTopics, listTagsForResource) => {
    var topicArn = (listTopics && listTopics.length) ? listTopics[0].TopicArn : null;
    return {
        sns: {
            listTopics: {
                'us-east-1': {
                    data: listTopics
                },
            },
            listTagsForResource: {
                'us-east-1': {
                    [topicArn]: {
                        data: listTagsForResource
                    },
                },
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
            listTagsForResource: {
                'us-east-1': {
                    err: {
                        message: 'error while getting topic attributes'
                    },
                }
            }
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
            listTagsForResource: {
                'us-east-1': {
                    [listTopics[0].TopicArn]: {
                        err: {
                            message: 'error while getting topic attributes'
                        },
                    }
                }
            }
        },
    };
};

const createNullCache = () => {
    return {
        sns: {
            listTopics: {
                'us-east-1': null,
            },
            listTagsForResource: {
                'us-east-1': null,
            },
        },
    };
};


describe('snsTopicHasTags', function () {
    describe('run', function () {
        it('should PASS if SNS topic has tags', function (done) {
            const cache = createCache([listTopics[0]], listTagsForResource[1]);
            snsTopicHasTags.run(cache, {}, (err, results) => {
                console.log(results)
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if SNS topic does not have tags', function (done) {
            const cache = createCache([listTopics[1]], listTagsForResource[0]);
            snsTopicHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no SNS topics found', function (done) {
            const cache = createCache([]);
            snsTopicHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error while listing SNS topics', function (done) {
            const cache = createErrorCache();
            snsTopicHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if error while getting tags for SNS topic', function (done) {
            const cache = createTopicAttributesErrorCache([listTopics[0]]);
            snsTopicHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if unable to list SNS topics', function (done) {
            const cache = createNullCache();
            snsTopicHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});