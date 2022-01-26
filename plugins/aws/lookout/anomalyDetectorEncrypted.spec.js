var expect = require('chai').expect;
var anomalyDetectorEncrypted = require('./anomalyDetectorEncrypted');

const listAnomalyDetectors = [    
    {
        "AnomalyDetectorArn": "arn:aws:lookoutmetrics:us-east-1:101363889637:AnomalyDetector:sadeed1",
        "AnomalyDetectorName": "sadeed1",
        "CreationTime": "2021-12-16T14:55:07.608000+05:00",
        "LastModificationTime": "2021-12-16T14:55:07.609000+05:00",
        "Status": "INACTIVE",
        "Tags": {}
    },
    {
        "AnomalyDetectorArn": "arn:aws:lookoutmetrics:us-east-1:000011112222:AnomalyDetector:sadeed2",
        "AnomalyDetectorName": "sadeed2",
        "CreationTime": "2021-12-16T14:55:07.608000+05:00",
        "LastModificationTime": "2021-12-16T14:55:07.609000+05:00",
        "Status": "INACTIVE",
        "Tags": {}
    }
];

const describeAnomalyDetector = [
    {
        "AnomalyDetectorArn": "arn:aws:lookoutmetrics:us-east-1:000011112222:AnomalyDetector:sadeed1",
        "AnomalyDetectorName": "sadeed1",
        "AnomalyDetectorConfig": {
            "AnomalyDetectorFrequency": "PT5M"
        },
        "CreationTime": "2021-12-16T14:55:07.608000+05:00",
        "LastModificationTime": "2021-12-16T14:55:07.609000+05:00",
        "Status": "INACTIVE",
        "KmsKeyArn": "arn:aws:kms:us-east-1:101363889637:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    },
    {
        "AnomalyDetectorArn": "arn:aws:lookoutmetrics:us-east-1:000011112222:AnomalyDetector:sadeed2",
        "AnomalyDetectorName": "sadeed2",
        "AnomalyDetectorConfig": {
            "AnomalyDetectorFrequency": "PT5M"
        },
        "CreationTime": "2021-12-16T14:55:07.608000+05:00",
        "LastModificationTime": "2021-12-16T14:55:07.609000+05:00",
        "Status": "INACTIVE",
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

const createCache = (detectors, keys, describeAnomalyDetector, describeKey, detectorsErr, keysErr, describeKeyErr, describeAnomalyDetectorErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var detectorArn = (detectors && detectors.length) ? detectors[0].AnomalyDetectorArn: null;
    return {
        lookoutmetrics: {
            listAnomalyDetectors: {
                'us-east-1': {
                    err: detectorsErr,
                    data: detectors
                },
            },
            describeAnomalyDetector: {
                'us-east-1': {
                    [detectorArn]: {
                        data: describeAnomalyDetector,
                        err: describeAnomalyDetectorErr
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

describe('anomalyDetectorEncrypted', function () {
    describe('run', function () {
        it('should PASS if LookoutMetrics Anomaly Detector is encrypted with desired encryption level', function (done) {
            const cache = createCache([listAnomalyDetectors[0]], listKeys, describeAnomalyDetector[0], describeKey[0]);
            anomalyDetectorEncrypted.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if LookoutMetrics Anomaly Detector is not encrypted with desired encryption level', function (done) {
            const cache = createCache([listAnomalyDetectors[1]], listKeys, describeAnomalyDetector[1], describeKey[1]);
            anomalyDetectorEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no LookoutMetrics Anomaly Detectors found', function (done) {
            const cache = createCache([]);
            anomalyDetectorEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list LookoutMetrics Anomaly Detectors', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list LookoutMetrics Anomaly Detectors" });
            anomalyDetectorEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listAnomalyDetectors, null, null, null, { message: "Unable to list KMS keys" });
            anomalyDetectorEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})
