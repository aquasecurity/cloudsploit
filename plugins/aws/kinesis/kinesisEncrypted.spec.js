var expect = require('chai').expect;
var kinesisEncrypted = require('./kinesisEncrypted');

const listStreams = [    
    "mine2"
];

const describeStream = [
    {
        "StreamDescription": {
        "Shards": [
            {
                "ShardId": "shardId-000000000000",
                "HashKeyRange": {
                    "StartingHashKey": "0",
                    "EndingHashKey": "340282366920938463463374607431768211455"
                },
                "SequenceNumberRange": {
                    "StartingSequenceNumber": "49625248393108116739567127156011434883828455224553504770"
                }
            }
        ],
        "StreamARN": "arn:aws:kinesis:us-east-1:101363889637:stream/mine2",
        "StreamName": "mine2",
        "StreamStatus": "ACTIVE",
        "RetentionPeriodHours": 24,
        "EnhancedMonitoring": [
            {
                "ShardLevelMetrics": []
            }
        ],
        "EncryptionType": "KMS",
        "KeyId": "alias/aws/kinesis",
        "StreamCreationTimestamp": "2021-12-27T19:27:41+05:00"
    }
    },
    {
        "StreamDescription": {
        "Shards": [
            {
                "ShardId": "shardId-000000000000",
                "HashKeyRange": {
                    "StartingHashKey": "0",
                    "EndingHashKey": "340282366920938463463374607431768211455"
                },
                "SequenceNumberRange": {
                    "StartingSequenceNumber": "49625248607195270645461109314754330301252766913651539970"
                }
            }
        ],
        "StreamARN": "arn:aws:kinesis:us-east-1:101363889637:stream/mine1",
        "StreamName": "mine1",
        "StreamStatus": "ACTIVE",
        "RetentionPeriodHours": 24,
        "EnhancedMonitoring": [
            {
                "ShardLevelMetrics": []
            }
        ],
        "EncryptionType": "NONE",
        "KeyId": null,
        "StreamCreationTimestamp": "2021-12-27T19:37:41+05:00"
    }
    },
    {
        "StreamDescription": {
        "Shards": [
            {
                "ShardId": "shardId-000000000000",
                "HashKeyRange": {
                    "StartingHashKey": "0",
                    "EndingHashKey": "340282366920938463463374607431768211455"
                },
                "SequenceNumberRange": {
                    "StartingSequenceNumber": "49625248607195270645461109314754330301252766913651539970"
                }
            }
        ],
        "StreamARN": "arn:aws:kinesis:us-east-1:101363889637:stream/mine1",
        "StreamName": "mine1",
        "StreamStatus": "ACTIVE",
        "RetentionPeriodHours": 24,
        "EnhancedMonitoring": [
            {
                "ShardLevelMetrics": []
            }
        ],
        "EncryptionType": "KMS",
        "KeyId": "arn:aws:kms:us-east-1:101363889637:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "StreamCreationTimestamp": "2021-12-27T19:37:41+05:00"
    }
    }
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

const createCache = (streams, keys, describeStream, describeKey, streamsErr, keysErr, describeKeyErr, describeStreamErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var stream = (streams && streams.length) ? streams[0]: null;
    return {
        kinesis: {
            listStreams: {
                'us-east-1': {
                    err: streamsErr,
                    data: streams
                },
            },
            describeStream: {
                'us-east-1': {
                    [stream]: {
                        data: describeStream,
                        err: describeStreamErr
                    }
                }
            }
        },
        kms: {
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

describe('kinesisEncrypted', function () {
    describe('run', function () {
        it('should PASS if Kinesis stream uses a KMS key for SSE', function (done) {
            const cache = createCache([listStreams[0]], listKeys, describeStream[2], describeKey[0]);
            kinesisEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The Kinesis stream uses a KMS key for SSE');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if The Kinesis stream does not use a KMS key for SSE', function (done) {
            const cache = createCache([listStreams[0]],listKeys, describeStream[1], describeKey[1]);
            kinesisEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The Kinesis stream does not use a KMS key for SSE');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should WARN if Kinesis stream uses the default KMS key', function (done) {
            const cache = createCache([listStreams[0]],listKeys, describeStream[0], describeKey[1]);
            kinesisEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).to.include('The Kinesis stream uses the default KMS key');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if No Kinesis streams found', function (done) {
            const cache = createCache([]);
            kinesisEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Kinesis streams found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Kinesis streams', function (done) {
            const cache = createCache(null, null, null, null, { message: "Unable to list Kinesis streams" });
            kinesisEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listStreams, null, null, null, { message: "Unable to list KMS keys" });
            kinesisEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})