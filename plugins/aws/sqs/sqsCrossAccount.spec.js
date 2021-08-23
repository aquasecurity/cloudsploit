const expect = require('chai').expect;
const sqsCrossAccount = require('./sqsCrossAccount');

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
            "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__owner_statement\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111222333444:root\"},\"Action\":\"SQS:*\",\"Resource\":\"arn:aws:sqs:us-east-1:112233445566:test1152.fifo\"}]}",
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
                            "Id": "112233445566",
                            "Arn": "arn:aws:organizations::112233445566:account/o-sb9qmv2zif/112233445566",
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

describe('sqsCrossAccount', function () {
    describe('run', function () {
        it('should FAIL if SQS queue SQS queue policy allows global access', function (done) {
            const cache = createCache([listQueues[0]], queueAttributes[0]);
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if SQS queue policy allows cross-account access', function (done) {
            const cache = createCache([listQueues[1]], queueAttributes[1]);
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if cross-account is whitelisted', function (done) {
            const cache = createCache([listQueues[1]], queueAttributes[1]);
            sqsCrossAccount.run(cache, { sqs_whitelisted_aws_account_principals:'arn:aws:iam::112233445566:root' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if SQS queue policy allows cross-account access to organization account and setting is set to true', function (done) {
            const cache = createCache([listQueues[1]], queueAttributes[1]);
            sqsCrossAccount.run(cache, { sqs_whitelist_aws_organization_accounts: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if SQS queue policy does not allow global or cross-account access', function (done) {
            const cache = createCache([listQueues[1]], queueAttributes[3]);
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no SQS queues found', function (done) {
            const cache = createCache([]);
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if SQS queues does not use a custom policy', function (done) {
            const cache = createCache([listQueues[3]], queueAttributes[2]);
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list SQS queues', function (done) {
            const cache = createErrorCache();
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });  
        
        it('should UNKNOWN if unable to query attributes for SQS queue', function (done) {
            const cache = createCache([listQueues[0]]);
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list SQS queues response not found', function (done) {
            const cache = createNullCache();
            sqsCrossAccount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});