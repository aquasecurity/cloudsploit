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
        "StreamARN": "arn:aws:kinesis:us-east-1:111122223333:stream/mine2",
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
        "StreamARN": "arn:aws:kinesis:us-east-1:111122223333:stream/mine1",
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
        "StreamARN": "arn:aws:kinesis:us-east-1:111122223333:stream/mine1",
        "StreamName": "mine1",
        "StreamStatus": "ACTIVE",
        "RetentionPeriodHours": 24,
        "EnhancedMonitoring": [
            {
                "ShardLevelMetrics": []
            }
        ],
        "EncryptionType": "KMS",
        "KeyId": "arn:aws:kms:us-east-1:111122223333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "StreamCreationTimestamp": "2021-12-27T19:37:41+05:00"
    }
    }
];

const createCache = (streams, describeStream, streamsErr, describeStreamErr) => {
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
    };
};

describe('kinesisEncrypted', function () {
    describe('run', function () {
        it('should PASS if Kinesis stream uses a KMS key for SSE', function (done) {
            const cache = createCache([listStreams[0]], describeStream[2]);
            kinesisEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The Kinesis stream uses a KMS key for SSE');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if The Kinesis stream does not use a KMS key for SSE', function (done) {
            const cache = createCache([listStreams[0]], describeStream[1]);
            kinesisEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The Kinesis stream does not use a KMS key for SSE');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should WARN if Kinesis stream uses the default KMS key', function (done) {
            const cache = createCache([listStreams[0]], describeStream[0]);
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
            const cache = createCache(null, null, { message: "Unable to list Kinesis streams" });
            kinesisEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Kinesis streams');
                done();
            });
        });

       
    });
})