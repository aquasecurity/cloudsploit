const expect = require('chai').expect;
const { queue } = require('async');
const sqsCrossAccount = require('./sqsCrossAccount');

const listQueues = [
    "https://sqs.us-east-1.amazonaws.com/112233445566/sqs-queue-1",
    "https://sqs.us-east-1.amazonaws.com/112233445566/sqs-queue-2",
    "https://sqs.us-east-1.amazonaws.com/112233445566/sqs-queue-3"
];

const getQueueAttributes = [
    {
        "Attributes": {
          "QueueArn": "arn:aws:sqs:us-east-1:112233445566:sqs-queue-1",
          "ApproximateNumberOfMessages": "0",
          "ApproximateNumberOfMessagesNotVisible": "0",
          "ApproximateNumberOfMessagesDelayed": "0",
          "CreatedTimestamp": "1601559156",
          "LastModifiedTimestamp": "1601559313",
          "VisibilityTimeout": "30",
          "MaximumMessageSize": "262144",
          "MessageRetentionPeriod": "345600",
          "DelaySeconds": "0",
          "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__owner_statement\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"SQS:*\",\"Resource\":\"arn:aws:sqs:us-east-1:112233445566:sqs-queue-1\"}]}",
          "ReceiveMessageWaitTimeSeconds": "0"
        }
    },
    {
        "Attributes": {
          "QueueArn": "arn:aws:sqs:us-east-1:112233445566:sqs-queue-2",
          "ApproximateNumberOfMessages": "0",
          "ApproximateNumberOfMessagesNotVisible": "0",
          "ApproximateNumberOfMessagesDelayed": "0",
          "CreatedTimestamp": "1601559156",
          "LastModifiedTimestamp": "1601559313",
          "VisibilityTimeout": "30",
          "MaximumMessageSize": "262144",
          "MessageRetentionPeriod": "345600",
          "DelaySeconds": "0",
          "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__owner_statement\",\"Effect\":\"Allow\",\"Principal\":\"arn:aws:iam::112233445566:root\",\"Action\":\"SQS:*\",\"Resource\":\"arn:aws:sqs:us-east-1:112233445566:sqs-queue-2\"}]}",
          "ReceiveMessageWaitTimeSeconds": "0"
        }
    },
    {
        "Attributes": {
          "QueueArn": "arn:aws:sqs:us-east-1:112233445566:sqs-queue-3",
          "ApproximateNumberOfMessages": "0",
          "ApproximateNumberOfMessagesNotVisible": "0",
          "ApproximateNumberOfMessagesDelayed": "0",
          "CreatedTimestamp": "1601559156",
          "LastModifiedTimestamp": "1601559313",
          "VisibilityTimeout": "30",
          "MaximumMessageSize": "262144",
          "MessageRetentionPeriod": "345600",
          "DelaySeconds": "0",
          "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__owner_statement\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\": \"arn:aws:iam::123456654321:root\"},\"Action\":\"SQS:*\",\"Resource\":\"arn:aws:sqs:us-east-1:112233445566:sqs-queue-3\"}]}",
          "ReceiveMessageWaitTimeSeconds": "0"
        }
    }
];

const getCallerIdentity = [
    "112233445566"
];

const createCache = (queues, queueAttributes, callerIdentity) => {
    var queueUrl = (queues && queues.length) ? queues[0] : null;
    return {
        sqs: {
            listQueues: {
                'us-east-1': {
                    data: queues,
                },
            },
            getQueueAttributes: {
                'us-east-1': {
                    [queueUrl]: {
                        data: queueAttributes
                    }
                }
            }
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: callerIdentity
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        sqs: {
            listQueues: {
                'us-east-1': { 
                    err: {
                        message: 'error listing SQS queues'
                    }
                }
            },
        },
    };
};

const createNullCache = () => {
    return {
        sqs: {
            listQueues: {
                'us-east-1': null,
            }
        },
    };
};

describe('sqsCrossAccount', function () {
    describe('run', function () {
        it('should FAIL if the SQS queue policy allows global access to the action(s)', function (done) {
            const cache = createCache([listQueues[0]], getQueueAttributes[0], getCallerIdentity[0]);
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if the SQS queue policy does not allow global or cross-account access', function (done) {
            const cache = createCache([listQueues[1]], getQueueAttributes[1], getCallerIdentity[0]);
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if the SQS queue policy allows trusted cross-account access to the action(s)', function (done) {
            const cache = createCache([listQueues[2]], getQueueAttributes[2], getCallerIdentity[0]);
            sqsCrossAccount.run(cache, { whitelisted_accounts:'123456654321' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if the SQS queue policy allows untrusted cross-account access to the action(s)', function (done) {
            const cache = createCache([listQueues[2]], getQueueAttributes[2], getCallerIdentity[0]);
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no SQS queues found', function (done) {
            const cache = createCache();
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0)
                done();
            });
        });

        it('should UNKNOWN if enable to query for SQS queues', function (done) {
            const cache = createErrorCache();
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list SQS queues response not found', function (done) {
            const cache = createNullCache();
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});