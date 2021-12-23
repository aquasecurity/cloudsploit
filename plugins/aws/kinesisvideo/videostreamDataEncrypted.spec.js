var expect = require('chai').expect;
var videostreamDataEncrypted = require('./videostreamDataEncrypted');


const listStreams = [
    {
        "StreamName": "test1",
        "StreamARN": "arn:aws:kinesisvideo:us-east-1:000111222333:stream/test1/1639473904764",
        "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "Version": "vsbqxi7p9kIu1AjRWBiv",
        "Status": "ACTIVE",
        "CreationTime": "2021-12-14T14:25:04.764000+05:00",
        "DataRetentionInHours": 24
    }
];

const listKeys = [
    {
        "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
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
            "Description": "Default master key that protects my kinesis video data when no other key is defined",
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
            "Description": "Default master key that protects my kinesis video data when no other key is defined",
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

const createCache = (streamData, keys, describeKey, streamDataErr, keysErr, describeKeyErr) => {
    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    return {
        kinesisvideo: {
            listStreams: {
                'us-east-1': {
                    err: streamDataErr,
                    data: streamData
                },
            },
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




describe('videostreamDataEncrypted', function () {
    describe('run', function () {
        it('should PASS if Kinesis Video Streams data is using desired encryption level', function (done) {
            const cache = createCache(listStreams, listKeys, describeKey[0]);
            videostreamDataEncrypted.run(cache, { video_stream_data_desired_encryption_level: 'awscmk' }, (err, results) => {
                console.log(results);
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Kinesis Video Streams data is using awscmk');
                done();
            });
        });


        it('should FAIL if Kinesis Video Streams data is using desired encyption level', function (done) {
            const cache = createCache(listStreams, listKeys, describeKey[1]);
            videostreamDataEncrypted.run(cache, { video_stream_data_desired_encryption_level:'awscmk' }, (err, results) => {
                console.log(results);
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Kinesis Video Streams data is using awskms');
                done();
            });
        });


        it('should PASS if no Kinesis Video Streams found', function (done) {
            const cache = createCache([]);
            videostreamDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Kinesis Video Streams found');
                done();
            });
        });

        it('should UNKNOWN if unable to list Kinesis Video Streams', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Kinesis Video Streams encryption" });
            videostreamDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, null, { message: "Unable to list KMS keys" });
            videostreamDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});