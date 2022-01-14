var expect = require('chai').expect;
var kendraIndexEncrypted = require('./kendraIndexEncrypted');

const listIndices = [    
    {
        "Name": "sadeed2",
        "Id": "1b5d0d81-224e-4a8b-bbc8-2c2a4a0a615c",
        "Edition": "DEVELOPER_EDITION",
        "CreatedAt": "2021-11-17T15:29:30.124000+05:00",
        "UpdatedAt": "2021-11-17T15:29:30.124000+05:00",
        "Status": "CREATING"
    },
    {
        "Name": "sadeed1",
        "Id": "9280dadd-5d45-4f9c-a105-896e5b230c05",
        "Edition": "DEVELOPER_EDITION",
        "CreatedAt": "2021-11-17T15:23:58.841000+05:00",
        "UpdatedAt": "2021-11-17T15:23:58.841000+05:00",
        "Status": "CREATING"
    }
];

const describeIndex = [
    {
    "Name": "sadeed1",
    "Id": "9280dadd-5d45-4f9c-a105-896e5b230c05",
    "Edition": "DEVELOPER_EDITION",
    "RoleArn": "arn:aws:iam::101363889637:role/service-role/AmazonKendra-us-east-1-role1",
    "ServerSideEncryptionConfiguration": {
        "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    },
    "Status": "ACTIVE",
    "CreatedAt": "2021-11-17T15:23:58.841000+05:00",
    "UpdatedAt": "2021-11-17T15:23:58.841000+05:00",
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

const createCache = (index, keys, describeIndex, describeKey, indexErr, keysErr, describeKeyErr, describeIndexErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var id = (index && index.length) ? index[0].Id: null;
    return {
        kendra: {
            listIndices: {
                'us-east-1': {
                    err: indexErr,
                    data: index
                },
            },
            describeIndex: {
                'us-east-1': {
                    [id]: {
                        data: describeIndex,
                        err: describeIndexErr
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

describe('kendraIndexEncrypted', function () {
    describe('run', function () {
        it('should PASS if Kendra Indices is encrypted with desired encryption level', function (done) {
            const cache = createCache([listIndices[0]], listKeys, describeIndex[0], describeKey[0]);
            kendraIndexEncrypted.run(cache, { kendra_index_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Kendra Indices is not encrypted with desired encryption level', function (done) {
            const cache = createCache([listIndices[1]],listKeys, describeIndex[0], describeKey[1]);
            kendraIndexEncrypted.run(cache, { kendra_index_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Kendra Indices found', function (done) {
            const cache = createCache([]);
            kendraIndexEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Kendra Indices', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Kendra Indices" });
            kendraIndexEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listIndices, null, null, null, { message: "Unable to list KMS keys" });
            kendraIndexEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})