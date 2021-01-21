const expect = require('chai').expect;
var sqsDeadLetterQueue = require('./sqsDeadLetterQueue');

const listQueues = [
        "https://sqs.us-east-1.amazonaws.com/111122223333/akd-31"
];

const getQueueAttributes = [
    {
        "Attributes": {
           "QueueArn":"arn:aws:sqs:us-east-1:111122223333:akd-31-2",
           "ApproximateNumberOfMessages":"0",
           "ApproximateNumberOfMessagesNotVisible":"0",
           "ApproximateNumberOfMessagesDelayed":"0",
           "CreatedTimestamp":"1609212146",
           "LastModifiedTimestamp":"1609212146",
           "VisibilityTimeout":"30",
           "MaximumMessageSize":"262144",
           "MessageRetentionPeriod":"345600",
           "DelaySeconds":"0",
           "Policy":"{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__owner_statement\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111122223333:root\"},\"Action\":\"SQS:*\",\"Resource\":\"arn:aws:sqs:us-east-1:111122223333:akd-31-2\"}]}",
           "RedrivePolicy":"{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:111122223333:akd-31\",\"maxReceiveCount\":10}",
           "ReceiveMessageWaitTimeSeconds":"0"
        }
    },
    {
        "Attributes": {
           "QueueArn":"arn:aws:sqs:us-east-1:111122223333:akd-31-2",
           "ApproximateNumberOfMessages":"0",
           "ApproximateNumberOfMessagesNotVisible":"0",
           "ApproximateNumberOfMessagesDelayed":"0",
           "CreatedTimestamp":"1609212146",
           "LastModifiedTimestamp":"1609212146",
           "VisibilityTimeout":"30",
           "MaximumMessageSize":"262144",
           "MessageRetentionPeriod":"345600",
           "DelaySeconds":"0",
           "Policy":"{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__owner_statement\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111122223333:root\"},\"Action\":\"SQS:*\",\"Resource\":\"arn:aws:sqs:us-east-1:111122223333:akd-31-2\"}]}",
           "ReceiveMessageWaitTimeSeconds":"0"
        }
    }
];



const createCache = (listQueues, getQueueAttributes, listQueuesErr, getQueueAttributesErr) => {
    var queueUrl = (listQueues && listQueues.length) ? listQueues[0] : null;
    return {
        sqs: {
            listQueues: {
                'us-east-1': {
                    err: listQueuesErr,
                    data: listQueues
                }
            },
            getQueueAttributes: {
                'us-east-1': {
                    [queueUrl]: {
                        err: getQueueAttributesErr,
                        data: getQueueAttributes
                    }
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

describe('sqsDeadLetterQueue', function () {
    describe('run', function () {
        it('should PASS if Amazon SQS queue has dead letter queue configured', function (done) {
            const cache = createCache([listQueues[0]], getQueueAttributes[0], null, null);
            sqsDeadLetterQueue.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Amazon SQS queue does not have dead letter queue configured', function (done) {
            const cache = createCache([listQueues[0]], getQueueAttributes[1], null, null);
            sqsDeadLetterQueue.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Amazon SQS queues found', function (done) {
            const cache = createCache([], null, null, null);
            sqsDeadLetterQueue.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for Amazon SQS queues', function (done) {
            const cache = createCache(listQueues, getQueueAttributes[1], { message: 'Unable to query for Amazon SQS queues'}, null);
            sqsDeadLetterQueue.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to query for Amazon SQS queue', function (done) {
            const cache = createCache(listQueues, getQueueAttributes[1], null, { message: 'Unable to query for Amazon SQS queue'});
            sqsDeadLetterQueue.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list queues response is not found', function (done) {
            const cache = createNullCache();
            sqsDeadLetterQueue.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
