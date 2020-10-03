const expect = require('chai').expect;
const sqsEncrypted = require('./sqsEncrypted');

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
          "ReceiveMessageWaitTimeSeconds": "0",
          "KmsMasterKeyId": 'arn:aws:kms:us-east-1:112233445566:key/f0b4f5a7-a7b5-47b8-b0bf-73203f562886'
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
          "ReceiveMessageWaitTimeSeconds": "0",
          "KmsMasterKeyId": 'alias/aws/sqs'
        }
    }
];

const createCache = (queues, queueAttributes) => {
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

describe('sqsEncrypted', function () {
    describe('run', function () {
        it('should FAIL if the SQS queue does not use a KMS key for SSE', function (done) {
            const cache = createCache([listQueues[0]], getQueueAttributes[0]);
            sqsEncrypted.run(cache, {}, (err, results) => {
                console.log(results);
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if the SQS queue uses a KMS key for SSE', function (done) {
            const cache = createCache([listQueues[1]], getQueueAttributes[1]);
            sqsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if the SQS queue uses the default KMS key for SSE', function (done) {
            const cache = createCache([listQueues[2]], getQueueAttributes[2]);
            sqsEncrypted.run(cache, { whitelisted_accounts:'123456654321' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should PASS if no SQS queues found', function (done) {
            const cache = createCache();
            sqsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0)
                done();
            });
        });

        it('should UNKNOWN if enable to query for SQS queues', function (done) {
            const cache = createErrorCache();
            sqsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list SQS queues response not found', function (done) {
            const cache = createNullCache();
            sqsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});