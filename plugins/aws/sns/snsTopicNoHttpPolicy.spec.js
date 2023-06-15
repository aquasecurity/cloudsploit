var expect = require('chai').expect;
var snsTopicnoHttpPolicy = require('./snsTopicNoHttpPolicy');


const listTopics = [
    { TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic' },
    { TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic-2' },
    { TopicArn: 'arn:aws:sns:us-east-1:111122223333:test-topic-2' }
];

const getTopicAttributes = [
    {
        "ResponseMetadata": "{\"RequestId\": '2a205b73-5c0d-55e2-8129-0ca612f4a41c' }",
        "Attributes": {
            "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"arn:aws:iam:112233445566"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1:111122223333:test-topic","Condition":{"StringEquals":{"AWS:SourceOwner":"111122223333"}}}]}',
            "Owner": '111122223333',
            "SubscriptionsPending": "0",
            "KmsMasterKeyId": 'alias/aws/sns',
            "TopicArn": 'arn:aws:sns:us-east-1:111122223333:test-topic',
            "EffectiveDeliveryPolicy": '{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,"numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false}}',
            "SubscriptionsConfirmed": "0",
            "DisplayName": "",
            "SubscriptionsDeleted": "0"
        }
    },
    {
        "ResponseMetadata": "{\"RequestId\": '2a205b73-5c0d-55e2-8129-0ca612f4a41c' }",
        "Attributes": {
          "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"arn:aws:iam:112233445566"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1:111122223333:test-topic","Condition":{"StringEquals":{"AWS:SourceOwner":"123456789012"}}},{"Sid":"__console_sub_0","Effect":"Deny","Principal":{"AWS":"*"},"Action":["SNS:Subscribe","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1: ... ","Condition":{"StringEquals":{"SNS:Protocol":"https"}}}]}',
          "SubscriptionsPending": "0",
          "KmsMasterKeyId": 'arn:aws:kms:us-east-1:111122223333:key/b8789907-b7f7-438d-847e-7d468bac86b2',
          "TopicArn": 'arn:aws:sns:us-east-1:111122223333:test-138-cmk',
          "EffectiveDeliveryPolicy": '{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,"numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false}}',
          "SubscriptionsConfirmed": "0",
          "DisplayName": "",
          "SubscriptionsDeleted": "0"
        }
    },
    {
        "ResponseMetadata": "{\"RequestId\": '2a205b73-5c0d-55e2-8129-0ca612f4a41c' }",
        "Attributes": {
          "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"arn:aws:iam:112233445566"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1:111122223333:test-topic","Condition":{"StringEquals":{"AWS:SourceOwner":"123456789012"}}},{"Sid":"__console_sub_0","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:Subscribe","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1: ... ","Condition":{"StringEquals":{"SNS:Protocol":"http"}}}]}',
          "SubscriptionsPending": "0",
          "KmsMasterKeyId": 'arn:aws:kms:us-east-1:111122223333:key/b8789907-b7f7-438d-847e-7d468bac86b2',
          "TopicArn": 'arn:aws:sns:us-east-1:111122223333:test-138-cmk',
          "EffectiveDeliveryPolicy": '{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,"numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false}}',
          "SubscriptionsConfirmed": "0",
          "DisplayName": "",
          "SubscriptionsDeleted": "0"
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


describe('snsTopicnoHttpPolicy', function () {
    describe('run', function () {
        it('should PASS if SNS topic policy does not allow http protocol', function (done) {
            const cache = createCache([listTopics[0]], getTopicAttributes[0]);
            snsTopicnoHttpPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('The SNS topic policy does not allow unsecured access via HTTP protocol.');
                done();
            });
        });

        it('should FAIL if SNS topic policy deny https protocol', function (done) {
            const cache = createCache([listTopics[1]], getTopicAttributes[1]);
            snsTopicnoHttpPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('The SNS topic policy allows unsecured access via HTTP protocol.');
                done();
            });
        });

        it('should FAIL if SNS topic policy allow http protocol', function (done) {
            const cache = createCache([listTopics[1]], getTopicAttributes[2]);
            snsTopicnoHttpPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('The SNS topic policy allows unsecured access via HTTP protocol.');
                done();
            });
        });

        it('should PASS if no SNS topics found', function (done) {
            const cache = createCache([]);
            snsTopicnoHttpPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No SNS topics found');
                done();
            });
        });

        it('should UNKNOWN if unable to list SNS topics', function (done) {
            const cache = createErrorCache();
            snsTopicnoHttpPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for SNS topics: ');
                done();
            });
        });

        it('should UNKNOWN if unable to get SNS topic attributes', function (done) {
            const cache = createTopicAttributesErrorCache([listTopics[0]]);
            snsTopicnoHttpPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query SNS topic for policy: ');
                done();
            });
        });

        it('should not return anything if list SNS topics response is not found', function (done) {
            const cache = createNullCache();
            snsTopicnoHttpPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
