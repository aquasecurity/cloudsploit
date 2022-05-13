var expect = require('chai').expect;
var firehoseEncrypted = require('./firehoseEncrypted');

const listDeliveryStreams = [    
    "KDS-S3-VzT52"
];

const describeDeliveryStream = [
    {
        "DeliveryStreamDescription": {
            "DeliveryStreamName": "KDS-S3-VzT52",
            "DeliveryStreamARN": "arn:aws:firehose:us-east-1:111122223333:deliverystream/KDS-S3-VzT52",
            "DeliveryStreamStatus": "ACTIVE",
            "DeliveryStreamEncryptionConfiguration": {
                "Status": "DISABLED"
            },
            "DeliveryStreamType": "DirectPut",
            "VersionId": "3",
            "CreateTimestamp": "2021-12-27T20:10:18.843000+05:00",
            "LastUpdateTimestamp": "2021-12-27T20:25:45.912000+05:00",
            "Destinations": [
                {
                    "DestinationId": "destinationId-000000000001",
                    "S3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::111122223333:role/service-role/KinesisFirehoseServiceRole-KDS-S3-VzT52-us-east-1-1640617752463",
                        "BucketARN": "arn:aws:s3:::guardduty-bucket-viteace",
                        "Prefix": "",
                        "ErrorOutputPrefix": "",
                        "BufferingHints": {
                            "SizeInMBs": 5,
                            "IntervalInSeconds": 300
                        },
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {
                            "NoEncryptionConfig": "NoEncryption"
                        },
                        "CloudWatchLoggingOptions": {
                            "Enabled": true,
                            "LogGroupName": "/aws/kinesisfirehose/KDS-S3-VzT52",
                            "LogStreamName": "DestinationDelivery"
                        }
                    },
                    "ExtendedS3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::111122223333:role/service-role/KinesisFirehoseServiceRole-KDS-S3-VzT52-us-east-1-1640617752463",
                        "BucketARN": "arn:aws:s3:::guardduty-bucket-viteace",
                        "Prefix": "",
                        "ErrorOutputPrefix": "",
                        "BufferingHints": {
                            "SizeInMBs": 5,
                            "IntervalInSeconds": 300
                        },
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {
                            "NoEncryptionConfig": "NoEncryption"
                        },
                        "CloudWatchLoggingOptions": {
                            "Enabled": true,
                            "LogGroupName": "/aws/kinesisfirehose/KDS-S3-VzT52",
                            "LogStreamName": "DestinationDelivery"
                        },
                        "ProcessingConfiguration": {
                            "Enabled": false,
                            "Processors": []
                        },
                        "S3BackupMode": "Disabled",
                        "DataFormatConversionConfiguration": {
                            "Enabled": false
                        }
                    }
                }
            ],
            "HasMoreDestinations": false
        }
    },
    {
        "DeliveryStreamDescription": {
            "DeliveryStreamName": "KDS-S3-VzT52",
            "DeliveryStreamARN": "arn:aws:firehose:us-east-1:111122223333:deliverystream/KDS-S3-VzT52",
            "DeliveryStreamStatus": "ACTIVE",
            "DeliveryStreamEncryptionConfiguration": {
                "Status": "DISABLED"
            },
            "DeliveryStreamType": "DirectPut",
            "VersionId": "3",
            "CreateTimestamp": "2021-12-27T20:10:18.843000+05:00",
            "LastUpdateTimestamp": "2021-12-27T20:25:45.912000+05:00",
            "Destinations": [
                {
                    "DestinationId": "destinationId-000000000001",
                    "S3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::111122223333:role/service-role/KinesisFirehoseServiceRole-KDS-S3-VzT52-us-east-1-1640617752463",
                        "BucketARN": "arn:aws:s3:::guardduty-bucket-viteace",
                        "Prefix": "",
                        "ErrorOutputPrefix": "",
                        "BufferingHints": {
                            "SizeInMBs": 5,
                            "IntervalInSeconds": 300
                        },
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {
                            "KMSEncryptionConfig": "NoEncryption"
                        },
                        "CloudWatchLoggingOptions": {
                            "Enabled": true,
                            "LogGroupName": "/aws/kinesisfirehose/KDS-S3-VzT52",
                            "LogStreamName": "DestinationDelivery"
                        }
                    },
                    "ExtendedS3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::111122223333:role/service-role/KinesisFirehoseServiceRole-KDS-S3-VzT52-us-east-1-1640617752463",
                        "BucketARN": "arn:aws:s3:::guardduty-bucket-viteace",
                        "Prefix": "",
                        "ErrorOutputPrefix": "",
                        "BufferingHints": {
                            "SizeInMBs": 5,
                            "IntervalInSeconds": 300
                        },
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {
                            "KMSEncryptionConfig": "arn:aws:kms:us-east-1:111122223333:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
                        },
                        "CloudWatchLoggingOptions": {
                            "Enabled": true,
                            "LogGroupName": "/aws/kinesisfirehose/KDS-S3-VzT52",
                            "LogStreamName": "DestinationDelivery"
                        },
                        "ProcessingConfiguration": {
                            "Enabled": false,
                            "Processors": []
                        },
                        "S3BackupMode": "Disabled",
                        "DataFormatConversionConfiguration": {
                            "Enabled": false
                        }
                    }
                }
            ],
            "HasMoreDestinations": false
        }
    },
    {
        "DeliveryStreamDescription": {
            "DeliveryStreamName": "KDS-S3-VzT52",
            "DeliveryStreamARN": "arn:aws:firehose:us-east-1:111122223333:deliverystream/KDS-S3-VzT52",
            "DeliveryStreamStatus": "ACTIVE",
            "DeliveryStreamEncryptionConfiguration": {
                "KeyType": "AWS_OWNED_CMK",
                "Status": "ENABLED"
            },
            "DeliveryStreamType": "DirectPut",
            "VersionId": "3",
            "CreateTimestamp": "2021-12-27T20:10:18.843000+05:00",
            "LastUpdateTimestamp": "2021-12-27T20:25:45.912000+05:00",
            "Destinations": [
                {
                    "DestinationId": "destinationId-000000000001",
                    "S3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::111122223333:role/service-role/KinesisFirehoseServiceRole-KDS-S3-VzT52-us-east-1-1640617752463",
                        "BucketARN": "arn:aws:s3:::guardduty-bucket-viteace",
                        "Prefix": "",
                        "ErrorOutputPrefix": "",
                        "BufferingHints": {
                            "SizeInMBs": 5,
                            "IntervalInSeconds": 300
                        },
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {
                            "KMSEncryptionConfig": "defaultKmsKey"
                        },
                        "CloudWatchLoggingOptions": {
                            "Enabled": true,
                            "LogGroupName": "/aws/kinesisfirehose/KDS-S3-VzT52",
                            "LogStreamName": "DestinationDelivery"
                        }
                    },
                    "ExtendedS3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::111122223333:role/service-role/KinesisFirehoseServiceRole-KDS-S3-VzT52-us-east-1-1640617752463",
                        "BucketARN": "arn:aws:s3:::guardduty-bucket-viteace",
                        "Prefix": "",
                        "ErrorOutputPrefix": "",
                        "BufferingHints": {
                            "SizeInMBs": 5,
                            "IntervalInSeconds": 300
                        },
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {
                            "KMSEncryptionConfig": "defaultKmsKey"
                        },
                        "CloudWatchLoggingOptions": {
                            "Enabled": true,
                            "LogGroupName": "/aws/kinesisfirehose/KDS-S3-VzT52",
                            "LogStreamName": "DestinationDelivery"
                        },
                        "ProcessingConfiguration": {
                            "Enabled": false,
                            "Processors": []
                        },
                        "S3BackupMode": "Disabled",
                        "DataFormatConversionConfiguration": {
                            "Enabled": false
                        }
                    }
                }
            ],
            "HasMoreDestinations": false
        }
    }
];


const createCache = (streams, describeDeliveryStream, streamsErr, describeDeliveryStreamErr) => {
    var stream = (streams && streams.length) ? streams[0]: null;
    return {
        firehose: {
            listDeliveryStreams: {
                'us-east-1': {
                    err: streamsErr,
                    data: streams
                },
            },
            describeDeliveryStream: {
                'us-east-1': {
                    [stream]: {
                        data: describeDeliveryStream,
                        err: describeDeliveryStreamErr
                    }
                }
            }
        },
    };
};

describe('firehoseEncrypted', function () {
    describe('run', function () {
        it('should PASS if Firehose delivery stream uses a KMS key for SSE', function (done) {
            const cache = createCache([listDeliveryStreams[0]], describeDeliveryStream[1]);
            firehoseEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The Firehose delivery stream uses a KMS key for SSE');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Firehose delivery stream does not use a KMS key for SSE', function (done) {
            const cache = createCache([listDeliveryStreams[0]], describeDeliveryStream[0]);
            firehoseEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The Firehose delivery stream does not use a KMS key for SSE');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

 
        it('should PASS if No Firehose delivery streams found', function (done) {
            const cache = createCache([]);
            firehoseEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Firehose delivery streams found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if Unable to list Firehose delivery streams', function (done) {
            const cache = createCache(null, null, { message: "Unable to list Firehose delivery streams" });
            firehoseEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list Firehose delivery streams');
                done();
            });
        });

        it('should UNKNOWN if unable to query Firehose for delivery streams', function (done) {
            const cache = createCache([listDeliveryStreams[0]], null, null,  { message: "Unable to Unable to query Firehose for delivery streams" });
            firehoseEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query Firehose for delivery streams');
                done();
            });
        });
    });
})