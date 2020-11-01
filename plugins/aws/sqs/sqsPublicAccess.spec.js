const expect = require('chai').expect;
const sqsPublicAccess = require('./sqsPublicAccess');

const listQueues = [
    "https://sqs.us-east-1.amazonaws.com/112233445566/test1152",
    "https://sqs.us-east-1.amazonaws.com/112233445566/test1152.fifo",
    "https://sqs.us-east-1.amazonaws.com/112233445566/test1153.fifo",
    "https://sqs.us-east-1.amazonaws.com/112233445566/test1153"
];

const queueAttributes = [
    {
        "Attributes": {
            "QueueArn": "arn:aws:sqs:us-east-1:112233445566:test1152",
            "ApproximateNumberOfMessages": "0",
            "ApproximateNumberOfMessagesNotVisible": "0",
            "ApproximateNumberOfMessagesDelayed": "0",
            "CreatedTimestamp": "1601240312",
            "LastModifiedTimestamp": "1601240664",
            "VisibilityTimeout": "30",
            "MaximumMessageSize": "262144",
            "MessageRetentionPeriod": "345600",
            "DelaySeconds": "0",
            "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__owner_statement\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"SQS:*\",\"Resource\":\"arn:aws:sqs:us-east-1:112233445566:test1152\"}]}",
            "ReceiveMessageWaitTimeSeconds": "0"
        }
    },
    {
        "Attributes": {
            "QueueArn": "arn:aws:sqs:us-east-1:112233445566:test1152.fifo",
            "ApproximateNumberOfMessages": "0",
            "ApproximateNumberOfMessagesNotVisible": "0",
            "ApproximateNumberOfMessagesDelayed": "0",
            "CreatedTimestamp": "1601242252",
            "LastModifiedTimestamp": "1601242252",
            "VisibilityTimeout": "30",
            "MaximumMessageSize": "262144",
            "MessageRetentionPeriod": "345600",
            "DelaySeconds": "0",
            "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__owner_statement\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::112233445566:root\"},\"Action\":\"SQS:*\",\"Resource\":\"arn:aws:sqs:us-east-1:112233445566:test1152.fifo\"}]}",
            "ReceiveMessageWaitTimeSeconds": "0",
            "FifoQueue": "true",
            "ContentBasedDeduplication": "false"
        }
    },
    {
        "Attributes": {
            "QueueArn": "arn:aws:sqs:us-east-1:112233445566:test1153",
            "ApproximateNumberOfMessages": "0",
            "ApproximateNumberOfMessagesNotVisible": "0",
            "ApproximateNumberOfMessagesDelayed": "0",
            "CreatedTimestamp": "1601242252",
            "LastModifiedTimestamp": "1601242252",
            "VisibilityTimeout": "30",
            "MaximumMessageSize": "262144",
            "MessageRetentionPeriod": "345600",
            "DelaySeconds": "0",
            "ReceiveMessageWaitTimeSeconds": "0",
            "FifoQueue": "true",
            "ContentBasedDeduplication": "false"
        }
    }
];

const createCache = (queues, attributes) => {
    var queueUrl = (queues && queues.length) ? queues[0] : null;
    return {
        sqs: {
            listQueues: {
                'us-east-1': {
                    data: queues
                }
            },
            getQueueAttributes: {
                'us-east-1': {
                    [queueUrl]: {
                        data: attributes
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
                    err: 'error while listing SQS queues'
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        sqs: {
            listQueues: {
                'us-east-1': null
            }
        }
    };
};

describe('sqsPublicAccess', function () {
    describe('run', function () {
        it('should FAIL if SQS queue is publically accessible', function (done) {
            const cache = createCache([listQueues[0]], queueAttributes[0]);
            sqsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if SQS queue is not publically accessible', function (done) {
            const cache = createCache([listQueues[1]], queueAttributes[1]);
            sqsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no SQS queues found', function (done) {
            const cache = createCache([]);
            sqsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if SQS queues does not use a custom policy', function (done) {
            const cache = createCache([listQueues[3]], queueAttributes[2]);
            sqsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list SQS queues', function (done) {
            const cache = createErrorCache();
            sqsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });  
        
        it('should UNKNOWN if unable to query attributes for SQS queue', function (done) {
            const cache = createCache([listQueues[2]]);
            sqsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list SQS queues response not found', function (done) {
            const cache = createNullCache();
            sqsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});