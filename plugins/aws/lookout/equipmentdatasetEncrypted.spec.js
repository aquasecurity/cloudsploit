var expect = require('chai').expect;
var equipmentdatasetEncrypted = require('./equipmentdatasetEncrypted');

const listDatasets = [    
    {
        "DatasetName": "sadeed1",
        "DatasetArn": "arn:aws:lookoutequipment:us-east-1:000011112222:dataset/sadeed1/7e416b3a-c317-44ed-9f51-1430d2191319",
        "Status": "CREATED",
        "CreatedAt": "2021-12-15T20:25:41.181000+05:00"
    },
    {
        "DatasetName": "sadeed2",
        "DatasetArn": "arn:aws:lookoutequipment:us-east-1:000011112222:dataset/sadeed2/7e416b3a-c317-44ed-9f51-1430d2191319",
        "Status": "CREATED",
        "CreatedAt": "2021-12-15T20:25:41.181000+05:00"
    }
];

const describeDataset = [
    {
        "DatasetName": "sadeed1",
        "DatasetArn": "arn:aws:lookoutequipment:us-east-1:000011112222:dataset/sadeed1/7e416b3a-c317-44ed-9f51-1430d2191319",
        "CreatedAt": "2021-12-15T20:25:41.181000+05:00",
        "LastUpdatedAt": "2021-12-15T20:25:41.181000+05:00",
        "Status": "CREATED",
        "Schema": "{\"Components\":[{\"ComponentName\":\"test1\",\"Columns\":[{\"Name\":\"Timestamp\",\"Type\":\"DATETIME\"},{\"Name\":\"Attr1\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr2\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr3\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr4\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr5\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr6\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr7\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr8\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr9\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr10\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr11\",\"Type\":\"DOUBLE\"}]}]}",
        "ServerSideKmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    },
    {
        "DatasetName": "sadeed1",
        "DatasetArn": "arn:aws:lookoutequipment:us-east-1:000011112222:dataset/sadeed1/7e416b3a-c317-44ed-9f51-1430d2191319",
        "CreatedAt": "2021-12-15T20:25:41.181000+05:00",
        "LastUpdatedAt": "2021-12-15T20:25:41.181000+05:00",
        "Status": "CREATED",
        "Schema": "{\"Components\":[{\"ComponentName\":\"test1\",\"Columns\":[{\"Name\":\"Timestamp\",\"Type\":\"DATETIME\"},{\"Name\":\"Attr1\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr2\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr3\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr4\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr5\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr6\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr7\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr8\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr9\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr10\",\"Type\":\"DOUBLE\"},{\"Name\":\"Attr11\",\"Type\":\"DOUBLE\"}]}]}",
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

const createCache = (datasets, keys, describeDataset, describeKey, datasetsErr, keysErr, describeKeyErr, describeDatasetErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var datasetName = (datasets && datasets.length) ? datasets[0].DatasetName: null;
    return {
        lookoutequipment: {
            listDatasets: {
                'us-east-1': {
                    err: datasetsErr,
                    data: datasets
                },
            },
            describeDataset: {
                'us-east-1': {
                    [datasetName]: {
                        data: describeDataset,
                        err: describeDatasetErr
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

describe('equipmentdatasetEncrypted', function () {
    describe('run', function () {
        it('should PASS if LookoutEquipment Dataset is encrypted with desired encryption level', function (done) {
            const cache = createCache([listDatasets[0]], listKeys, describeDataset[0], describeKey[0]);
            equipmentdatasetEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if LookoutEquipment Dataset is not encrypted with desired encryption level', function (done) {
            const cache = createCache([listDatasets[1]], listKeys, describeDataset[1], describeKey[1]);
            equipmentdatasetEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no LookoutEquipment Datasets found', function (done) {
            const cache = createCache([]);
            equipmentdatasetEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list LookoutEquipment Datasets', function (done) {
            const cache = createCache([listDatasets[1]], listKeys, describeDataset[1], describeKey[1], { message: "Unable to list LookoutEquipment Datasets" });
            equipmentdatasetEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listDatasets, null, null, null, null, { message: "Unable to list KMS keys" });
            equipmentdatasetEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})
