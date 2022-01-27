var expect = require('chai').expect;
var sqsEncryptionEnabled = require('./sqsEncryptionEnabled');

const listQueues = [
    "https://sqs.us-east-1.amazonaws.com/000111222333/akhtarqueue"
];


const getQueueAttributes = [
    {
        "ResponseMetadata": {
          "RequestId": "55fecb32-ba74-528f-bea8-9174eb61d3d5"
        },
        "Attributes": {
          "QueueArn": "arn:aws:sqs:us-east-1:000111222333:my-queue1",
          "ApproximateNumberOfMessages": "0",
          "ApproximateNumberOfMessagesNotVisible": "0",
          "ApproximateNumberOfMessagesDelayed": "0",
          "CreatedTimestamp": "1640774167",
          "LastModifiedTimestamp": "1640774167",
          "VisibilityTimeout": "30",
          "MaximumMessageSize": "262144",
          "MessageRetentionPeriod": "345600",
          "DelaySeconds": "0",
          "ReceiveMessageWaitTimeSeconds": "0",
          "KmsMasterKeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
          "KmsDataKeyReusePeriodSeconds": "300",
          "SqsManagedSseEnabled": "false"
        }
    },
    {
        "ResponseMetadata": {
          "RequestId": "8b46adeb-a313-5f7a-8319-f7adf206f5ed"
        },
        "Attributes": {
          "QueueArn": "arn:aws:sqs:us-east-1:000111222333:mine1",
          "ApproximateNumberOfMessages": "0",
          "ApproximateNumberOfMessagesNotVisible": "0",
          "ApproximateNumberOfMessagesDelayed": "0",
          "CreatedTimestamp": "1640704710",
          "LastModifiedTimestamp": "1640775981",
          "VisibilityTimeout": "30",
          "MaximumMessageSize": "262144",
          "MessageRetentionPeriod": "345600",
          "DelaySeconds": "0",
          "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__owner_statement\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::101363889637:root\"},\"Action\":\"SQS:*\",\"Resource\":\"arn:aws:sqs:us-east-1:101363889637:mine1\"}]}",
          "ReceiveMessageWaitTimeSeconds": "0",
          "SqsManagedSseEnabled": "true"
        }
    },
    {
        "ResponseMetadata": {
          "RequestId": "d35d9102-91c9-5a3b-b8e0-cb44c0dcd106"
        },
        "Attributes": {
          "QueueArn": "arn:aws:sqs:us-east-1:000111222333:akhtarqueue",
          "ApproximateNumberOfMessages": "0",
          "ApproximateNumberOfMessagesNotVisible": "0",
          "ApproximateNumberOfMessagesDelayed": "0",
          "CreatedTimestamp": "1637571406",
          "LastModifiedTimestamp": "1637577249",
          "VisibilityTimeout": "30",
          "MaximumMessageSize": "262144",
          "MessageRetentionPeriod": "345600",
          "DelaySeconds": "0",
          "Policy": "{\"Version\":\"2012-10-17\",\"Id\":\"appman-infrastructure-sqs-ce-status-sync\",\"Statement\":[{\"Sid\":\"appman-infrastructure-sqs-ce-status-sync-policy\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::101363889637:root\"},\"Action\":\"SQS:*\",\"Resource\":\"arn:aws:sqs:us-east-1:101363889637:akhtarqueue\"},{\"Effect\":\"Allow\",\"Action\":\"kms:*\",\"Resource\":\"arn:aws:sqs:us-east-1:101363889637:akhtarqueue\"},{\"Sid\":\"appman-infrastructure-sns-sqs-ce-status-sync-policy\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"SQS:SendMessage\",\"Resource\":\"arn:aws:sqs:us-east-1:101363889637:akhtarqueue\",\"Condition\":{\"ArnLike\":{\"aws:SourceArn\":\"arn:aws:sns:eu-west-1:827604522863:applicant-manager-status-changed\"}}}]}",
          "ReceiveMessageWaitTimeSeconds": "0",
          "SqsManagedSseEnabled": "false"
        }
    }
];

const listAliases = [
    {
        "AliasName": "alias/sadeed-k1",
        "AliasArn": "arn:aws:kms:us-east-1:000111222333:alias/sadeed-k1",
        "TargetKeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "CreationDate": "2021-11-15T17:05:31.308000+05:00",
        "LastUpdatedDate": "2021-11-15T17:05:31.308000+05:00"
    },
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "AWS",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    }
];

const listKeys = [
    {
        "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
]

const createCache = (queues, keys, kmsAliases, getQueueAttributes, describeKey, queuesErr, kmsAliasesErr, keysErr, describeKeyErr, getQueueAttributesErr) => {

    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    var queue = (queues && queues.length) ? queues[0]: null;
    return {
        sqs: {
            listQueues: {
                'us-east-1': {
                    err: queuesErr,
                    data: queues
                },
            },
            getQueueAttributes: {
                'us-east-1': {
                    [queue]: {
                        data: getQueueAttributes,
                        err: getQueueAttributesErr
                    }
                }
            }
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    data: kmsAliases,
                    err: kmsAliasesErr
                },
            },
            listKeys: {
                'us-east-1': {
                    data: keys,
                    err: keysErr
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        err: describeKeyErr,
                        data: describeKey
                    },
                },
            },
        },
    };
};

describe('sqsEncryptionEnabled', function () {
    describe('run', function () {
        it('should PASS if SQS queue is encrypted with desired encryption level', function (done) {
            const cache = createCache([listQueues[0]], listKeys, listAliases, getQueueAttributes[0], describeKey[0]);
            sqsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQS queue is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if SQS queue not encrypted with desired encryption level', function (done) {
            const cache = createCache([listQueues[0]], listKeys, listAliases, getQueueAttributes[1], describeKey[1]);
            sqsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQS queue is encrypted with sse');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if SQS queue does not have encryption enabled', function (done) {
            const cache = createCache([listQueues[0]], listKeys, listAliases, getQueueAttributes[2], describeKey[1]);
            sqsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQS queues does not have encryption enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no SQS queues found', function (done) {
            const cache = createCache([]);
            sqsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQS queues found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query SQS queues', function (done) {
            const cache = createCache([listQueues[0]], listKeys, listAliases, null, null, null, null, 
                null, null,  { message: "Unable to query SQS queues" });
            sqsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query SQS queues');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listQueues, null, null, null, null, null, null, { message: "Unable to list KMS keys" });
            sqsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list KMS keys');
                done();
            });
        });
    });
})
