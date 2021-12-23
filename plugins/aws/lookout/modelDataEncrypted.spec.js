const expect = require('chai').expect;
var modelDataEncrypted = require('./modelDataEncrypted');


const listProjects = [
    {
        "ProjectArn": "arn:aws:lookoutvision:us-east-1:000011112222:project/hgvhg",
        "ProjectName": "hgvhg",
        "CreationTimestamp": "2021-12-17T15:48:01.894000+05:00"
    }
];

const listModels = [  
    {
        "CreationTimestamp": "2021-12-17T16:36:51.745000+05:00",
        "ModelVersion": "2",
        "ModelArn": "arn:aws:lookoutvision:us-east-1:000011112222:model/hgvhg/2",
        "Status": "TRAINING_FAILED",
        "StatusMessage": "Images in the dataset must have the same dimensions."
    },
    {
        "CreationTimestamp": "2021-12-17T16:30:44.844000+05:00",
        "ModelVersion": "1",
        "ModelArn": "arn:aws:lookoutvision:us-east-1:000011112222:model/hgvhg/1",
        "Status": "TRAINING_FAILED",
        "StatusMessage": "Images in the dataset must have the same dimensions."
    }
];

const describeModel = [
    {
        "ModelDescription": {
            "ModelVersion": "2",
            "ModelArn": "arn:aws:lookoutvision:us-east-1:000011112222:model/hgvhg/2",
            "CreationTimestamp": "2021-12-17T16:36:51.745000+05:00",
            "Status": "TRAINING_FAILED",
            "StatusMessage": "Images in the dataset must have the same dimensions.",
            "OutputConfig": {
                "S3Location": {
                    "Bucket": "lookoutvision-us-east-1-7a197cd243",
                    "Prefix": "projects/hgvhg/models/"
                }
            }
        }
    },
    {
        "ModelDescription": {
            "ModelVersion": "1",
            "ModelArn": "arn:aws:lookoutvision:us-east-1:000011112222:model/hgvhg/1",
            "CreationTimestamp": "2021-12-17T16:30:44.844000+05:00",
            "Status": "TRAINING_FAILED",
            "StatusMessage": "Images in the dataset must have the same dimensions.",
            "OutputConfig": {
                "S3Location": {
                    "Bucket": "lookoutvision-us-east-1-7a197cd243",
                    "Prefix": "projects/hgvhg/models/"
                }
            },
            "KmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
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

const createCache = (listProjects, listModels,  describeModel, keys, describeKey, listProjectsErr, keysErr, listModelsErr, describeKeyErr, describeModelErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var projectName = (listProjects && listProjects.length) ? listProjects[0].ProjectName : null;
    var modelArn = (listModels && listModels.length) ? listModels[0].ModelArn : null;
    return {
        lookoutvision: {
            listProjects: {
                'us-east-1': {
                    err: listProjectsErr,
                    data: listProjects
                }
            },
            listModels: {
                'us-east-1': {
                    [projectName]: {
                        err: listModelsErr,
                        data: {
                            "Models": listModels
                        }     
                    }
                }
            },
            describeModel: {
                'us-east-1': {
                    [modelArn]: {
                        err: describeModelErr,
                        data: describeModel
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
        lookoutvision: {
            listProjects: {
                'us-east-1': null
            }
        }
    };
};

describe('modelDataEncrypted', function () {
    describe('run', function () {

        it('should PASS if LookoutVision model data is encrypted with desired level', function (done) {
            const cache = createCache([listProjects[0]], [listModels[1]], describeModel[1], listKeys, describeKey[0]);
            modelDataEncrypted.run(cache, { model_data_desired_encryption_level: 'awscmk' }, (err, results) => {
                console.log(results);
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if LookoutVision model data is not encrypted with desired level ', function (done) {
            const cache = createCache([listProjects[0]], [listModels[0]], describeModel[0], listKeys, describeKey[1]);
            modelDataEncrypted.run(cache, { model_data_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no projects found', function (done) {
            const cache = createCache([]);
            modelDataEncrypted.run(cache, { model_data_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list LookoutVision projects', function (done) {
            const cache = createCache(null, null, null, null, { message: 'Unable to list LookoutVision model'});
            modelDataEncrypted.run(cache, { model_data_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list LookoutVision models', function (done) {
            const cache = createCache([listProjects[0]], null, describeModel[0], listKeys, null, null, null, { message: 'Unable to query LookoutVision models'});
            modelDataEncrypted.run(cache, { model_data_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list projects response not found', function (done) {
            const cache = createNullCache();
            modelDataEncrypted.run(cache, { model_data_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache([listProjects[0]], null, null, null, null, null, { message: "Unable to list KMS keys" });
            modelDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});