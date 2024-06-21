var expect = require('chai').expect;
var customModelEncryptionEnabled = require('./customModelEncryptionEnabled');

const listCustomModels = [
    {
        "modelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/2ytyyx8nid0h",
        "modelName": "model2",
        "creationTime": "2023-11-29T10:45:43.056000+00:00",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "baseModelName": ""
    },
    {
        "modelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/vjqsydtdhkpz",
        "modelName": "test-model",
        "creationTime": "2023-11-28T11:29:18.655000+00:00",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "baseModelName": ""
    }
];

const getCustomModel = [
    {
        "modelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/2ytyyx8nid0h",
        "modelName": "model2",
        "jobArn": "arn:aws:bedrock:us-east-1:11223344:model-customization-job/amazon.titan-text-lite-v1:0:4k/lo7152tvvl3f",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "modelKmsKeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
        "hyperParameters": {
            "batchSize": "2",
            "epochCount": "2",
            "learningRate": "0.00001",
            "learningRateWarmupSteps": "0"
        },
        "trainingDataConfig": {
            "s3Uri": "s3://bedrockbuckettest/trainigdata.jsonl"
        },
        "outputDataConfig": {
            "s3Uri": "s3://bedrockbuckettest"
        },
        "trainingMetrics": {
            "trainingLoss": 1.7109375
        },
        "validationMetrics": [],
        "creationTime": "2023-11-29T10:45:43.056000+00:00"
    },
    {
        "modelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/vjqsydtdhkpz",
        "modelName": "test-model",
        "jobArn": "arn:aws:bedrock:us-east-1:11223344:model-customization-job/amazon.titan-text-lite-v1:0:4k/iuvltioettou",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "hyperParameters": {
            "batchSize": "2",
            "epochCount": "2",
            "learningRate": "0.00001",
            "learningRateWarmupSteps": "0"
        },
        "trainingDataConfig": {
            "s3Uri": "s3://bedrockbuckettest/trainigdata.jsonl"
        },
        "outputDataConfig": {
            "s3Uri": "s3://bedrockbuckettest"
        },
        "trainingMetrics": {
            "trainingLoss": 1.7109375
        },
        "validationMetrics": [],
        "creationTime": "2023-11-28T11:29:18.655000+00:00"
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
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
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0252",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0252",
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
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
    },
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/f4942dd6-bce5-4213-bdd3-cc8ccd87dd890"
    }
]
const createCache = (customModel, getCustomModel, keys, describeKey, customModelErr, getCustomModelErr, keysErr, describeKeyErr) => {
    var modelName = (customModel && customModel.length) ? customModel[0].modelName: null;
    var keyId = (keys && keys.length) ? keys[0].KeyArn.split('/')[1] : null;
    return {
        bedrock: {
            listCustomModels: {
                'us-east-1': {
                    err: customModelErr,
                    data: customModel
                },
            },
            getCustomModel: {
                'us-east-1': {
                    [modelName]: {
                        data: getCustomModel,
                        err: getCustomModelErr
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

describe('customModelEncryptionEnabled', function () {
    describe('run', function () {
        it('should PASS if Bedrock Custom Model is Encrypted using CMK', function (done) {
            const cache = createCache([listCustomModels[0]], getCustomModel[0], listKeys, describeKey[0]);
            customModelEncryptionEnabled.run(cache, {bedrock_model_desired_encryption_level: 'awscmk'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Bedrock Custom Model is encrypted with AWS owned key', function (done) {
            const cache = createCache([listCustomModels[1]], getCustomModel[1], listKeys, describeKey[1]);
            customModelEncryptionEnabled.run(cache, {bedrock_model_desired_encryption_level: 'awscmk'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if the desired encryption level for bedrock custom model is awskms', function (done) {
            const cache = createCache([listCustomModels[1]], getCustomModel[1], listKeys, describeKey[1]);
            customModelEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Bedrock custom model found', function (done) {
            const cache = createCache([]);
            customModelEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Bedrock custom model', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Bedrock Custom Model" });
            customModelEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})

