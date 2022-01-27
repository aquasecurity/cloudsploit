var expect = require('chai').expect;
var kinesisDataStreamsEncrypted = require('./kinesisDataStreamsEncrypted');

const listStreams = [
    "mine2",
    "mine3"
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
                        "StartingSequenceNumber": "49625307919684448350212376424208934206295946525447028738"
                    }
                }
            ],
            "StreamARN": "arn:aws:kinesis:us-east-1:000011112222:stream/mine2",
            "StreamName": "mine2",
            "StreamStatus": "ACTIVE",
            "RetentionPeriodHours": 24,
            "EnhancedMonitoring": [
                {
                    "ShardLevelMetrics": []
                }
            ],
            "EncryptionType": "KMS",
            "KeyId": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "StreamCreationTimestamp": "2021-12-29T17:48:10+05:00"
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
                        "StartingSequenceNumber": "49625308470958869657889380482971889906163549124874469378"
                    }
                }
            ],
            "StreamARN": "arn:aws:kinesis:us-east-1:000011112222:stream/mine3",
            "StreamName": "mine3",
            "StreamStatus": "ACTIVE",
            "RetentionPeriodHours": 24,
            "EnhancedMonitoring": [
                {
                    "ShardLevelMetrics": []
                }
            ],
            "EncryptionType": "KMS",
            "KeyId": "alias/aws/kinesis",
            "StreamCreationTimestamp": "2021-12-29T18:13:55+05:00"
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
                        "StartingSequenceNumber": "49625308561945910067894322900437620458568881592741134338"
                    }
                }
            ],
            "StreamARN": "arn:aws:kinesis:us-east-1:000011112222:stream/mine1",
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
            "StreamCreationTimestamp": "2021-12-29T18:18:10+05:00"
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
    {
        "AliasName": "alias/aws/kinesis",
        "AliasArn": "arn:aws:kms:us-east-1:000111222333:alias/aws/kinesis",
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

const createCache = (streams, keys, kmsAliases, describeStream, describeKey, streamsErr, kmsAliasesErr, keysErr, describeKeyErr, describeStreamErr) => {

    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
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

describe('kinesisDataStreamsEncrypted', function () {
    describe('run', function () {
        it('should PASS if Kinesis stream is encrypted with desired encryption level', function (done) {
            const cache = createCache([listStreams[0]], listKeys, [listAliases[0]], describeStream[0], describeKey[0]);
            kinesisDataStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Kinesis stream is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Kinesis stream not encrypted with desired encryption level', function (done) {
            const cache = createCache([listStreams[1]], listKeys, [listAliases[1]], describeStream[1], describeKey[1]);
            kinesisDataStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Kinesis stream is encrypted with awskms');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Kinesis streams does not have encryption enabled', function (done) {
            const cache = createCache([listStreams[0]], listKeys, listAliases, describeStream[2], describeKey[1]);
            kinesisDataStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Kinesis stream does not have encryption enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Kinesis streams found', function (done) {
            const cache = createCache([]);
            kinesisDataStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Kinesis streams found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to to query for Kinesis streams', function (done) {
            const cache = createCache([listStreams[0]], listKeys, listAliases, null, null, null, null, null, null ,{ message: "Unable to to query for Kinesis streams" });
            kinesisDataStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Kinesis for stream');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listStreams, null, null, null, null, null, null, { message: "Unable to list KMS keys" });
            kinesisDataStreamsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list KMS keys');
                done();
            });
        });
    });
})