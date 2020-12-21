var expect = require('chai').expect;
const topicEncrypted = require('./topicEncrypted');


const listTopics = [
    { TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic-137' },
    { TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic-137-2' }
];

const getTopicAttributes = [
    {
        ResponseMetadata: { RequestId: '2a205b73-5c0d-55e2-8129-0ca612f4a41c' },
        Attributes: {
            Policy: '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1:111122223333:test-topic-137","Condition":{"StringEquals":{"AWS:SourceOwner":"111122223333"}}}]}',
            Owner: '111122223333',
            SubscriptionsPending: '0',
            KmsMasterKeyId: 'alias/aws/sns',
            TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic-137',
            EffectiveDeliveryPolicy: '{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,"numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false}}',
            SubscriptionsConfirmed: '0',
            DisplayName: '',
            SubscriptionsDeleted: '0'
        }
    },
    {
        ResponseMetadata: { RequestId: '20222ee7-0216-5ec4-ad6e-79324cef93b7' },
        Attributes: {
            Policy: '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1:111122223333:test-topic-137-2","Condition":{"StringEquals":{"AWS:SourceOwner":"111122223333"}}}]}',
            Owner: '111122223333',
            SubscriptionsPending: '0',
            TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic-137-2',
            EffectiveDeliveryPolicy: '{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,"numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false}}',
            SubscriptionsConfirmed: '0',
            DisplayName: '',
            SubscriptionsDeleted: '0'
        }
    }
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


describe('topicEncrypted', function () {
    describe('run', function () {
        it('should PASS if Server-Side Encryption is enabled for SNS topic', function (done) {
            const cache = createCache([listTopics[0]], getTopicAttributes[0]);
            topicEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Server-Side Encryption is not enabled for SNS topic', function (done) {
            const cache = createCache([listTopics[1]], getTopicAttributes[1]);
            topicEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no SNS topics found', function (done) {
            const cache = createCache([]);
            topicEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error while listing SNS topics', function (done) {
            const cache = createErrorCache();
            topicEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if error while getting SNS topic attributes', function (done) {
            const cache = createTopicAttributesErrorCache([listTopics[0]]);
            topicEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if unable to list SNS topics', function (done) {
            const cache = createNullCache();
            topicEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});