var expect = require('chai').expect;
var geoCollectionDataEncrypted = require('./geoCollectionDataEncrypted');

const listGeofenceCollections = [    
    {
        "CollectionName": "sadeed1",
        "CreateTime": "2021-12-15T12:39:55.016000+00:00",
        "Description": "",
        "PricingPlan": "MobileAssetTracking",
        "PricingPlanDataSource": "Here",
        "UpdateTime": "2021-12-15T12:39:55.016000+00:00"
    },
    {
        "CollectionName": "explore.geofence-collection",
        "CreateTime": "2021-12-14T14:15:06.967000+00:00",
        "Description": "Created by Amazon Location Service explore",
        "PricingPlan": "RequestBasedUsage",
        "UpdateTime": "2021-12-14T14:15:06.967000+00:00"
    }
    
];

const describeGeofenceCollection = [
    {
        "CollectionArn": "arn:aws:geo:us-east-1:000111222333:geofence-collection/sadeed1",
        "CollectionName": "sadeed1",
        "CreateTime": "2021-12-15T12:39:55.016000+00:00",
        "Description": "",
        "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "PricingPlan": "MobileAssetTracking",
        "PricingPlanDataSource": "Here",
        "Tags": {},
        "UpdateTime": "2021-12-15T12:39:55.016000+00:00"
    },
    {
        "CollectionArn": "arn:aws:geo:us-east-1:000111222333:geofence-collection/explore.geofence-collection",
        "CollectionName": "explore.geofence-collection",
        "CreateTime": "2021-12-14T14:15:06.967000+00:00",
        "Description": "Created by Amazon Location Service explore",
        "PricingPlan": "RequestBasedUsage",
        "Tags": {},
        "UpdateTime": "2021-12-14T14:15:06.967000+00:00"
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

const createCache = (collection, keys, describeGeofenceCollection, describeKey, collectionErr, keysErr, describeKeyErr, describeGeofenceCollectionErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var collectionName = (collection && collection.length) ? collection[0].CollectionName: null;
    return {
        location: {
            listGeofenceCollections: {
                'us-east-1': {
                    err: collectionErr,
                    data: collection
                },
            },
            describeGeofenceCollection: {
                'us-east-1': {
                    [collectionName]: {
                        data: describeGeofenceCollection,
                        err: describeGeofenceCollectionErr
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

describe('geoCollectionDataEncrypted', function () {
    describe('run', function () {
        it('should PASS if Location geoference collection data is encrypted with desired encryption level', function (done) {
            const cache = createCache([listGeofenceCollections[0]], listKeys, describeGeofenceCollection[0], describeKey[0]);
            geoCollectionDataEncrypted.run(cache, { geoference_collectiondata_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Location geoference collection data is not encrypted with desired encryption level', function (done) {
            const cache = createCache([listGeofenceCollections[1]], listKeys, describeGeofenceCollection[1], describeKey[1]);
            geoCollectionDataEncrypted.run(cache, { geoference_collectiondata_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Location geoference collections found', function (done) {
            const cache = createCache([]);
            geoCollectionDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Location geoference collections', function (done) {
            const cache = createCache(null, null, null, null, { message: "Unable to list Location geoference collections" });
            geoCollectionDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listGeofenceCollections, null, null, null, null, { message: "Unable to list KMS keys" });
            geoCollectionDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})