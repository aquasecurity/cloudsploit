var expect = require('chai').expect;
var trackerDataEncrypted = require('./trackerDataEncrypted');

const listTrackers = [    
    {
        "CreateTime": "2021-12-14T14:15:06.971000+00:00",
        "Description": "Created by Amazon Location Service explore",
        "PricingPlan": "RequestBasedUsage",
        "TrackerName": "explore.tracker",
        "UpdateTime": "2021-12-14T14:15:06.971000+00:00"
    },
    {
        "CreateTime": "2021-12-15T11:58:23.483000+00:00",
        "Description": "",
        "PricingPlan": "MobileAssetTracking",
        "PricingPlanDataSource": "Here",
        "TrackerName": "mytracker1",
        "UpdateTime": "2021-12-15T11:58:23.483000+00:00"
    }
];

const describeTracker = [
    {
        "CreateTime": "2021-12-15T11:58:23.483000+00:00",
        "Description": "",
        "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "PricingPlan": "MobileAssetTracking",
        "PricingPlanDataSource": "Here",
        "Tags": {},
        "TrackerArn": "arn:aws:geo:us-east-1:000111222333:tracker/mytracker1",
        "TrackerName": "mytracker1",
        "UpdateTime": "2021-12-15T11:58:23.483000+00:00"
    },
    {
        "CreateTime": "2021-12-14T14:15:06.971000+00:00",
        "Description": "Created by Amazon Location Service explore",
        "PricingPlan": "RequestBasedUsage",
        "Tags": {},
        "TrackerArn": "arn:aws:geo:us-east-1:000111222333:tracker/explore.tracker",
        "TrackerName": "explore.tracker",
        "UpdateTime": "2021-12-14T14:15:06.971000+00:00"
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

const createCache = (trackers, keys, describeTracker, describeKey, trackersErr, keysErr, describeKeyErr, describeTrackerErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var tracker = (trackers && trackers.length) ? trackers[0].TrackerName: null;
    return {
        location: {
            listTrackers: {
                'us-east-1': {
                    err: trackersErr,
                    data: trackers
                },
            },
            describeTracker: {
                'us-east-1': {
                    [tracker]: {
                        data: describeTracker,
                        err: describeTrackerErr
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

describe('trackerDataEncrypted', function () {
    describe('run', function () {
        it('should PASS if Location tracker data is encrypted with desired encryption level', function (done) {
            const cache = createCache([listTrackers[0]], listKeys, describeTracker[0], describeKey[0]);
            trackerDataEncrypted.run(cache, { location_trackerdata_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Location tracker data is not encrypted with desired encryption level', function (done) {
            const cache = createCache([listTrackers[1]], listKeys, describeTracker[1], describeKey[1]);
            trackerDataEncrypted.run(cache, { location_trackerdata_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Location tracker found', function (done) {
            const cache = createCache([]);
            trackerDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Location tracker', function (done) {
            const cache = createCache(null, null, null, null, { message: "Unable to list Location tracker" });
            trackerDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listTrackers, null, null, null, null, { message: "Unable to list KMS keys" });
            trackerDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})