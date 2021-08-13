const expect = require('chai').expect;
const snsCrossAccount = require('./snsCrossAccount');

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
          "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1:111122223333:test-138-cmk","Condition":{"StringEquals":{"AWS:SourceOwner":"111122223333"}}}]}',
          "Owner": '111122223333',
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
            "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__default_statement_ID\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":[\"SNS:GetTopicAttributes\",\"SNS:SetTopicAttributes\",\"SNS:AddPermission\",\"SNS:RemovePermission\",\"SNS:DeleteTopic\",\"SNS:Subscribe\",\"SNS:ListSubscriptionsByTopic\",\"SNS:Publish\",\"SNS:Receive\"],\"Resource\":\"arn:aws:sns:us-east-1:111222333444:test-spec\",\"Condition\":{}}]}",
            "Owner": "111122223333",
            "SubscriptionsPending": "0",
            "TopicArn": "arn:aws:sns:us-east-1:111122223333:test-spec",
            "EffectiveDeliveryPolicy": "{\"http\":{\"defaultHealthyRetryPolicy\":{\"minDelayTarget\":20,\"maxDelayTarget\":20,\"numRetries\":3,\"numMaxDelayRetries\":0,\"numNoDelayRetries\":0,\"numMinDelayRetries\":0,\"backoffFunction\":\"linear\"},\"disableSubscriptionOverrides\":false}}",
            "SubscriptionsConfirmed": "0",
            "DisplayName": "",
            "SubscriptionsDeleted": "0"
        }
    },
    {
        "ResponseMetadata": "{\"RequestId\": '2a205b73-5c0d-55e2-8129-0ca612f4a41c' }",
        "Attributes": {
            "Owner": '111122223333',
            "SubscriptionsPending": "0",
            "KmsMasterKeyId": 'alias/aws/sns',
            "TopicArn": 'arn:aws:sns:us-east-1:111122223333:test-topic',
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
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '111222333444'
                }
            }
        },
        organizations: {
            listAccounts: {
                'us-east-1': {
                    data: [
                        {
                            "Id": "111222333444",
                            "Arn": "arn:aws:organizations::111222333444:account/o-sb9qmv2zif/111222333444",
                            "Email": "xyz@gmail.com",
                            "Name": "test-role",
                            "Status": "ACTIVE",
                            "JoinedMethod": "INVITED",
                            "JoinedTimestamp": "2020-12-27T10:47:14.057Z"
                        },
                        {
                            "Id": "111122223333",
                            "Arn": "arn:aws:organizations::111122223333:account/o-sb9qmv2zif/111122223333",
                            "Email": "xyz@gmail.com",
                            "Name": "test-role",
                            "Status": "ACTIVE",
                            "JoinedMethod": "INVITED",
                            "JoinedTimestamp": "2020-12-27T10:47:14.057Z"
                        }
                    ]
                }
            }
        }
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

const createNullCache = () => {
    return {
        sns: {
            listTopics: {
                'us-east-1': null
            }
        }
    };
};

describe('snsCrossAccount', function () {
    describe('run', function () {
        it('should FAIL if SNS topic policy allows cross-account access', function (done) {
            const cache = createCache([listTopics[1]], getTopicAttributes[1]);
            snsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if cross-account is whitelisted', function (done) {
            const cache = createCache([listTopics[1]], getTopicAttributes[1]);
            snsCrossAccount.run(cache, { sns_whitelisted_aws_account_principals: '111122223333' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if SNS topic policy allows cross-account access to organization account and setting is set to true', function (done) {
            const cache = createCache([listTopics[1]], getTopicAttributes[1]);
            snsCrossAccount.run(cache, { sns_whitelist_aws_organization_accounts: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if SNS topic policy does not allow cross-account access', function (done) {
            const cache = createCache([listTopics[1]], getTopicAttributes[2]);
            snsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no SNS topics found', function (done) {
            const cache = createCache([]);
            snsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if SNS topic does not use a policy', function (done) {
            const cache = createCache([listTopics[1]], getTopicAttributes[3]);
            snsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list SNS topics', function (done) {
            const cache = createErrorCache();
            snsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });  
        
        it('should UNKNOWN if unable to query attributes for SNS topic', function (done) {
            const cache = createCache([listTopics[0]]);
            snsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list SNS topics response not found', function (done) {
            const cache = createNullCache();
            snsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});