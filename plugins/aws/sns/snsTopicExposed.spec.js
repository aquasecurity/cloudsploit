var expect = require('chai').expect;
var snsTopicExposed = require('./snsTopicExposed');


const listTopics = [
    { TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic' },
    { TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic-2' },
];

const getTopicAttributes = [
    {
        "Attributes": {
            "Policy": "{\"Version\":\"2012-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"testpolicy\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"us-east-1.testpolicy.amazonaws.com\"},\"Action\":\"sns:Publish\",\"Resource\":\"arn:aws:sns:us-east-1:111122223333:test-topic\",\"Condition\":{\"StringEquals\":{\"aws:SourceArn\":\"arn:aws:testpolicy:us-east-1: 111122223333:channel/8f347f19-b32d-4e19-b8cd-5494edab27cd\",\"aws:SourceAccount\":\" 111122223333\"}}},{\"Sid\":\"__default_statement_ID\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"us-east-1.testpolicy.amazonaws.com\"},\"Action\":[\"SNS:GetTopicAttributes\",\"SNS:SetTopicAttributes\",\"SNS:AddPermission\",\"SNS:RemovePermission\",\"SNS:DeleteTopic\",\"SNS:Subscribe\",\"SNS:ListSubscriptionsByTopic\",\"SNS:Publish\"],\"Resource\":\"arn:aws:sns:us-east-1:111122223333:test-topic\",\"Condition\":{\"StringEquals\":{\"AWS:SourceOwner\":\" 111122223333\"}}}]}",
            "TopicArn": "arn:aws:sns:us-east-1:111122223333:test-topic"
        },
    },
    {
        "Attributes": {
        "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__default_statement_ID\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":[\"SNS:Publish\",\"SNS:RemovePermission\",\"SNS:SetTopicAttributes\",\"SNS:DeleteTopic\",\"SNS:ListSubscriptionsByTopic\",\"SNS:GetTopicAttributes\",\"SNS:AddPermission\",\"SNS:Subscribe\"],\"Resource\":\" arn:aws:sns:us-east-1:111122223333:test-topic-2\",\"Condition\":{\"StringEquals\":{\"AWS:SourceOwner\":\"  111122223333\"}}}]}",
        "TopicArn": " arn:aws:sns:us-east-1:111122223333:test-topic-2",
        "TracingConfig": "PassThrough",
        "EffectiveDeliveryPolicy": "{\"http\":{\"defaultHealthyRetryPolicy\":{\"minDelayTarget\":20,\"maxDelayTarget\":20,\"numRetries\":3,\"numMaxDelayRetries\":0,\"numNoDelayRetries\":0,\"numMinDelayRetries\":0,\"backoffFunction\":\"linear\"},\"disableSubscriptionOverrides\":false,\"defaultRequestPolicy\":{\"headerContentType\":\"text/plain; charset=UTF-8\"}}}",
      },
    },
    {}
];

const createCache = (listTopics, getTopicAttributes) => {
    var topicArn = (listTopics && listTopics.length) ? listTopics[0].TopicArn : null;
    return {
        sns: {
            listTopics: {
                'us-east-1': {
                    data: listTopics
                },
            },
            getTopicAttributes: {
                'us-east-1': {
                    [topicArn]: {
                        data: getTopicAttributes
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
            getTopicAttributes: {
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
            getTopicAttributes: {
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
            getTopicAttributes: {
                'us-east-1': null,
            },
        },
    };
};


describe('snsTopicExposed', function () {
    describe('run', function () {
        it('should PASS if SNS topic is not publicly exposed', function (done) {
            const cache = createCache([listTopics[0]], getTopicAttributes[0]);
            snsTopicExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('The SNS topic is not publicly exposed.');
                done();
            });
        });

        it('should FAIL if SNS topic is publicly exposed', function (done) {
            const cache = createCache([listTopics[1]], getTopicAttributes[1]);
            snsTopicExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('The SNS topic is publicly exposed.');
                done();
            });
        });

        it('should FAIL if The SNS topic does not have a policy attached.', function (done) {
            const cache = createCache([listTopics[1]], getTopicAttributes[2]);
            snsTopicExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('The SNS topic does not have a policy attached.');
                done();
            });
        });

        it('should PASS if no SNS topics found', function (done) {
            const cache = createCache([]);
            snsTopicExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No SNS topics found');
                done();
            });
        });

        it('should UNKNOWN if unable to list SNS topics', function (done) {
            const cache = createErrorCache();
            snsTopicExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for SNS topics: ');
                done();
            });
        });

        it('should UNKNOWN if unable to get SNS topic attributes', function (done) {
            const cache = createTopicAttributesErrorCache([listTopics[0]]);
            snsTopicExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query SNS topic for policy: ');
                done();
            });
        });

        it('should not return anything if list SNS topics response is not found', function (done) {
            const cache = createNullCache();
            snsTopicExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
