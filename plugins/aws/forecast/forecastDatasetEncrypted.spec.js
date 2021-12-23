var expect = require('chai').expect;
var forecastDatasetEncrypted = require('./forecastDatasetEncrypted');


const listDatasets = [
    {
        "DatasetArn": "arn:aws:forecast:us-east-1:000011112222:dataset/testdataset",
        "DatasetName": "testdataset",
        "DatasetType": "ITEM_METADATA",
        "Domain": "RETAIL",
        "CreationTime": "2021-12-05T14:55:22.021000+05:00",
        "LastModificationTime": "2021-12-05T14:55:22.021000+05:00"
    },
];

const describeDataset = [
    {
        "DatasetArn": "arn:aws:forecast:us-east-1:000011112222:dataset/testdataset",
        "DatasetName": "testdataset",
        "Domain": "RETAIL",
        "DatasetType": "ITEM_METADATA",
        "Schema": {
            "Attributes": [
                {
                    "AttributeName": "item_name",
                    "AttributeType": "string"
                },
                {
                    "AttributeName": "item_id",
                    "AttributeType": "string"
                }
            ]
        },
        "EncryptionConfig": {
            "RoleArn": "arn:aws:iam::000011112222:role/service-role/AmazonForecast-ExecutionRole-1637334836508",
            "KMSKeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
        },
        "Status": "ACTIVE",
        "CreationTime": "2021-12-05T14:55:22.021000+05:00",
        "LastModificationTime": "2021-12-05T14:55:22.021000+05:00"
    },
    {
        "DatasetArn": "arn:aws:forecast:us-east-1:000011112222:dataset/testdataset",
        "DatasetName": "testdataset",
        "Domain": "RETAIL",
        "DatasetType": "ITEM_METADATA",
        "Schema": {
            "Attributes": [
                {
                    "AttributeName": "item_name",
                    "AttributeType": "string"
                },
                {
                    "AttributeName": "item_id",
                    "AttributeType": "string"
                }
            ]
        },
        "Status": "ACTIVE",
        "CreationTime": "2021-12-05T14:55:22.021000+05:00",
        "LastModificationTime": "2021-12-05T14:55:22.021000+05:00"
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
    }
];

const createCache = (datasets, describeDataset, keys, describeKey, datasetsErr, keysErr) => {
    let datasetArn = (datasets && datasets.length) ? datasets[0].DatasetArn : null;
    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    return {
        forecastservice: {
            listDatasets: {
                'us-east-1': {
                    err: datasetsErr,
                    data: datasets
                },
            },
            describeDataset: {
                'us-east-1': {
                    [datasetArn]: {
                        data: describeDataset
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
                        data: describeKey
                    },
                },
            },
        },
    };
};

describe('forecastDatasetEncrypted', function () {
    describe('run', function () {
        it('should PASS if Forecast dataset is encrypted with desired KMS key', function (done) {
            const cache = createCache(listDatasets, describeDataset[0], listKeys, describeKey[0]);
            forecastDatasetEncrypted.run(cache, { healthLake_data_store_encryption: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Forecast dataset is encrypted with awscmk');
                done();
            });
        });


        it('should FAIL if Forecast dataset is not encrypted with desired KMS key', function (done) {
            const cache = createCache(listDatasets, describeDataset[0], listKeys, describeKey[0]);
            forecastDatasetEncrypted.run(cache, { forecast_dataset_desired_encryption_level: 'externalcmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Forecast dataset is encrypted with awscmk');
                done();
            });
        });

        it('should FAIL if Forecast dataset is not encrypted', function (done) {
            const cache = createCache(listDatasets, describeDataset[1], listKeys, describeKey[0]);
            forecastDatasetEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Forecast dataset does not have encryption enabled');
                done();
            });
        });


        it('should PASS if no Forecast datasets found', function (done) {
            const cache = createCache([]);
            forecastDatasetEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Forecast datasets found');
                done();
            });
        });

        it('should UNKNOWN if unable to list Forecast datasets', function (done) {
            const cache = createCache(null, null, null, null, { message: "Unable to obtain data" });
            forecastDatasetEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Forecast datasets');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listDatasets, describeDataset[0], null, null, null, { message: "Unable to obtain data" });
            forecastDatasetEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list KMS keys');
                done();
            });
        });
    });
});