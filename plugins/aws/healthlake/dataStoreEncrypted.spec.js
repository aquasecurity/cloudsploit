var expect = require('chai').expect;
var dataStoreEncrypted = require('./dataStoreEncrypted');


const listFHIRDatastores = [
    {
        "DatastoreId": "7ad17b6c9d48056865a8800b86cc2797",
        "DatastoreArn": "arn:aws:healthlake:us-east-1:000111222333:datastore/fhir/7ad17b6c9d48056865a8800b86cc2797",            "DatastoreName": "sadeed-ds1",
        "DatastoreStatus": "ACTIVE",
        "CreatedAt": "2021-11-23T15:31:55.180000+05:00",
        "DatastoreTypeVersion": "R4",
        "DatastoreEndpoint": "https://healthlake.us-east-1.amazonaws.com/datastore/7ad17b6c9d48056865a8800b86cc2797/r4/",
        "SseConfiguration": {
            "KmsEncryptionConfig": {
                "CmkType": "CUSTOMER_MANAGED_KMS_KEY",
                "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
            }
        }
    },
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
            "KeyId": "2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
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
            "KeyId": "2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
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

const createCache = (datastore, keys, describeKey, datastoreErr, keysErr, describeKeyErr) => {
    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    return {
        healthlake: {
            listFHIRDatastores: {
                'us-east-1': {
                    err: datastoreErr,
                    data: datastore
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




describe('dataStoreEncrypted', function () {
    describe('run', function () {
        it('should PASS if HealthLake Data Store is encrypted with desired encryption level', function (done) {
            const cache = createCache(listFHIRDatastores, listKeys, describeKey[0]);
            dataStoreEncrypted.run(cache, { healthLake_data_store_encryption: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('HealthLake data store is encrypted with awscmk');
                done();
            });
        });


        it('should FAIL if HealthLake Data Store is not encrypted with desired encyption level', function (done) {
            const cache = createCache(listFHIRDatastores, listKeys, describeKey[1]);
            dataStoreEncrypted.run(cache, { healthLake_data_store_encryption:'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('HealthLake data store is encrypted with awskms');
                done();
            });
        });


        it('should PASS if no HealthLake Data Store found', function (done) {
            const cache = createCache([]);
            dataStoreEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No HealthLake data stores found');
                done();
            });
        });

        it('should UNKNOWN if unable to list HealthLake Data Store', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list HealthLake Data Store encryption" });
            dataStoreEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list KMS keys" });
            dataStoreEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});