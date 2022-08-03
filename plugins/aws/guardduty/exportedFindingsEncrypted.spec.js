const expect = require('chai').expect;
var exportedFindingsEncrypted = require('./exportedFindingsEncrypted');


const listDetectors = [
    "febe94ba60bad6400e7ea861564c3e23"     
];

const listPublishingDestinations = [  
    {
        "DestinationId": "b0bee1c1aca099effbcf75e6bad47ca4",
        "DestinationType": "S3",
        "Status": "PUBLISHING"
    }
];

const describePublishingDestination = [
    {
        "DestinationId": "b0bee1c1aca099effbcf75e6bad47ca4",
        "DestinationType": "S3",
        "Status": "PUBLISHING",
        "DestinationProperties": {
            "DestinationArn": "arn:aws:s3:::viteace-data-bucket",
            "KmsKeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
        }
    },
    {
        "DestinationId": "b0bee1c1aca099effbcf75e6bad47ca4",
        "DestinationType": "S3",
        "Status": "PUBLISHING",
        "DestinationProperties": {
            "DestinationArn": "arn:aws:s3:::viteace-data-bucket",
            "KmsKeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
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

const createCache = (listDetectors, listPublishingDestinations,  describePublishingDestination, keys, describeKey, listDetectorsErr, keysErr, listPublishingDestinationsErr, describeKeyErr, describePublishingDestinationErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var detectorsId = (listDetectors && listDetectors.length) ? listDetectors[0] : null;
    var destinationId = (listPublishingDestinations && listPublishingDestinations.length) ?
        listPublishingDestinations[0].DestinationId : null;
    return {
        guardduty: {
            listDetectors: {
                'us-east-1': {
                    err: listDetectorsErr,
                    data: listDetectors
                }
            },
            listPublishingDestinations: {
                'us-east-1': {
                    [detectorsId]: {
                        err: listPublishingDestinationsErr,
                        data: {
                            "Destinations": listPublishingDestinations
                        }
                    }
                }
            },
            describePublishingDestination: {
                'us-east-1': {
                    [destinationId]: {
                        err: describePublishingDestinationErr,
                        data: describePublishingDestination
                    }
                }
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

const createNullCache = () => {
    return {
        guardduty: {
            listDetectors: {
                'us-east-1': null
            }
        }
    };
};

describe('exportedFindingsEncrypted', function () {
    describe('run', function () {

        it('should PASS if GuardDuty Export Findings is encrypted with desired level', function (done) {
            const cache = createCache([listDetectors[0]], [listPublishingDestinations[0]], describePublishingDestination[0], listKeys, describeKey[0]);
            exportedFindingsEncrypted.run(cache, { exported_findings_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if GuardDuty Export Findings is not encrypted with desired level ', function (done) {
            const cache = createCache([listDetectors[0]], [listPublishingDestinations[0]], describePublishingDestination[1], listKeys, describeKey[1]);
            exportedFindingsEncrypted.run(cache, { exported_findings_desired_encryption_level: 'externalcmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if on GuardDuty detectors found', function (done) {
            const cache = createCache([]);
            exportedFindingsEncrypted.run(cache, { exported_findings_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list GuardDuty detectors', function (done) {
            const cache = createCache(null, null, null, null, null, { message: 'Unable to list GuardDuty detectors'});
            exportedFindingsEncrypted.run(cache, { exported_findings_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list GuardDuty publishing destinations', function (done) {
            const cache = createCache([listDetectors[0]], {}, describePublishingDestination[0], null, null, null, null, { message: 'Unable to query GuardDuty publishing destinations'});
            exportedFindingsEncrypted.run(cache, { exported_findings_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list detectors response not found', function (done) {
            const cache = createNullCache();
            exportedFindingsEncrypted.run(cache, { exported_findings_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache([listDetectors[0]], null, null, null, null, null, { message: "Unable to list KMS keys" });
            exportedFindingsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});