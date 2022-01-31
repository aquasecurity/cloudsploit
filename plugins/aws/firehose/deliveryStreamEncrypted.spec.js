var expect = require('chai').expect;
var deliveryStreamEncrypted = require('./deliveryStreamEncrypted');

const listDeliveryStreams = [
    "PUT-S3-YuZ2N"
];


const describeDeliveryStream = [
    {
        "DeliveryStreamDescription": {
            "DeliveryStreamName": "PUT-S3-YuZ2N",
            "DeliveryStreamARN": "arn:aws:firehose:us-east-1:000011112222:deliverystream/PUT-S3-YuZ2N",
            "DeliveryStreamStatus": "ACTIVE",
            "DeliveryStreamEncryptionConfiguration": {
                "Status": "DISABLED"
            },
            "DeliveryStreamType": "DirectPut",
            "VersionId": "2",
            "CreateTimestamp": "2021-12-29T19:11:13.718000+05:00",
            "LastUpdateTimestamp": "2021-12-29T19:39:12.160000+05:00",
            "Destinations": [
                {
                    "DestinationId": "destinationId-000000000001",
                    "S3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::000011112222:role/service-role/KinesisFirehoseServiceRole-PUT-S3-YuZ2N-us-east-1-1640786994734",
                        "BucketARN": "arn:aws:s3:::amazon-connect-5bc142a71067",
                        "Prefix": "",
                        "ErrorOutputPrefix": "",
                        "BufferingHints": {
                            "SizeInMBs": 5,
                            "IntervalInSeconds": 300
                        },
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {
                            "KMSEncryptionConfig": {
                                "AWSKMSKeyARN": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
                            }
                        },
                        "CloudWatchLoggingOptions": {
                            "Enabled": true,
                            "LogGroupName": "/aws/kinesisfirehose/PUT-S3-YuZ2N",
                            "LogStreamName": "DestinationDelivery"
                        }
                    },
                    "ExtendedS3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::000011112222:role/service-role/KinesisFirehoseServiceRole-PUT-S3-YuZ2N-us-east-1-1640786994734",
                        "BucketARN": "arn:aws:s3:::amazon-connect-5bc142a71067",
                        "Prefix": "",
                        "ErrorOutputPrefix": "",
                        "BufferingHints": {
                            "SizeInMBs": 5,
                            "IntervalInSeconds": 300
                        },
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {
                            "KMSEncryptionConfig": {
                                "AWSKMSKeyARN": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
                            }
                        },
                        "CloudWatchLoggingOptions": {
                            "Enabled": true,
                            "LogGroupName": "/aws/kinesisfirehose/PUT-S3-YuZ2N",
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
            "DeliveryStreamName": "PUT-S3-YuZ2N",
            "DeliveryStreamARN": "arn:aws:firehose:us-east-1:000011112222:deliverystream/PUT-S3-YuZ2N",
            "DeliveryStreamStatus": "ACTIVE",
            "DeliveryStreamEncryptionConfiguration": {
                "Status": "DISABLED"
            },
            "DeliveryStreamType": "DirectPut",
            "VersionId": "4",
            "CreateTimestamp": "2021-12-29T19:11:13.718000+05:00",
            "LastUpdateTimestamp": "2021-12-29T19:50:27.485000+05:00",
            "Destinations": [
                {
                    "DestinationId": "destinationId-000000000001",
                    "S3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::000011112222:role/service-role/KinesisFirehoseServiceRole-PUT-S3-YuZ2N-us-east-1-1640786994734",
                        "BucketARN": "arn:aws:s3:::amazon-connect-5bc142a71067",
                        "Prefix": "",
                        "ErrorOutputPrefix": "",
                        "BufferingHints": {
                            "SizeInMBs": 5,
                            "IntervalInSeconds": 300
                        },
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {
                            "KMSEncryptionConfig": {
                                "AWSKMSKeyARN": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
                            }
                        },
                        "CloudWatchLoggingOptions": {
                            "Enabled": true,
                            "LogGroupName": "/aws/kinesisfirehose/PUT-S3-YuZ2N",
                            "LogStreamName": "DestinationDelivery"
                        }
                    },
                    "ExtendedS3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::000011112222:role/service-role/KinesisFirehoseServiceRole-PUT-S3-YuZ2N-us-east-1-1640786994734",
                        "BucketARN": "arn:aws:s3:::amazon-connect-5bc142a71067",
                        "Prefix": "",
                        "ErrorOutputPrefix": "",
                        "BufferingHints": {
                            "SizeInMBs": 5,
                            "IntervalInSeconds": 300
                        },
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {
                            "KMSEncryptionConfig": {
                                "AWSKMSKeyARN": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
                            }
                        },
                        "CloudWatchLoggingOptions": {
                            "Enabled": true,
                            "LogGroupName": "/aws/kinesisfirehose/PUT-S3-YuZ2N",
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
            "DeliveryStreamName": "PUT-S3-YuZ2N",
            "DeliveryStreamARN": "arn:aws:firehose:us-east-1:000011112222:deliverystream/PUT-S3-YuZ2N",
            "DeliveryStreamStatus": "ACTIVE",
            "DeliveryStreamEncryptionConfiguration": {
                "Status": "DISABLED"
            },
            "DeliveryStreamType": "DirectPut",
            "VersionId": "3",
            "CreateTimestamp": "2021-12-29T19:11:13.718000+05:00",
            "LastUpdateTimestamp": "2021-12-29T19:40:18.084000+05:00",
            "Destinations": [
                {
                    "DestinationId": "destinationId-000000000001",
                    "S3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::000011112222:role/service-role/KinesisFirehoseServiceRole-PUT-S3-YuZ2N-us-east-1-1640786994734",
                        "BucketARN": "arn:aws:s3:::amazon-connect-5bc142a71067",
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
                            "LogGroupName": "/aws/kinesisfirehose/PUT-S3-YuZ2N",
                            "LogStreamName": "DestinationDelivery"
                        }
                    },
                    "ExtendedS3DestinationDescription": {
                        "RoleARN": "arn:aws:iam::000011112222:role/service-role/KinesisFirehoseServiceRole-PUT-S3-YuZ2N-us-east-1-1640786994734",
                        "BucketARN": "arn:aws:s3:::amazon-connect-5bc142a71067",
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
                            "LogGroupName": "/aws/kinesisfirehose/PUT-S3-YuZ2N",
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
    },
]

const createCache = (streams,  keys, describeDeliveryStream, describeKey, streamsErr, keysErr, describeKeyErr, describeDeliveryStreamErr) => {

    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
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

describe('deliveryStreamEncrypted', function () {
    describe('run', function () {
        it('should PASS if Firehose Delivery Stream is encrypted with desired encryption level', function (done) {
            const cache = createCache([listDeliveryStreams[0]], listKeys, describeDeliveryStream[0], describeKey[0]);
            deliveryStreamEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Firehose delivery stream is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Firehose Delivery Stream not encrypted with desired encryption level', function (done) {
            const cache = createCache([listDeliveryStreams[0]], listKeys, describeDeliveryStream[1], describeKey[1]);
            deliveryStreamEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Firehose delivery stream is encrypted with awskms');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Firehose Delivery Streams does not have encryption enabled', function (done) {
            const cache = createCache([listDeliveryStreams[0]], listKeys, describeDeliveryStream[2], describeKey[1]);
            deliveryStreamEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Firehose delivery stream does not have encryption enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Firehose Delivery Streams found', function (done) {
            const cache = createCache([]);
            deliveryStreamEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Firehose delivery streams found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Firehose Delivery Streams', function (done) {
            const cache = createCache(null, null, null, null, { message: "Unable to list Firehose Delivery Streams" });
            deliveryStreamEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list Firehose delivery streams');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if Unable to query Firehose for delivery streams', function (done) {
            const cache = createCache([listDeliveryStreams[0]], listKeys, null, null, null, null, null, { message: "query Firehose for delivery streams" });
            deliveryStreamEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Firehose for delivery streams');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listDeliveryStreams, null, null, null, null, { message: "Unable to list KMS keys" });
            deliveryStreamEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})