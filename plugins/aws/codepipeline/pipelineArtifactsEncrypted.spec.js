var expect = require('chai').expect;
var pipelineArtifactsEncrypted = require('./pipelineArtifactsEncrypted');

const listPipelines = [
   {   
    "name": "sad",
    "version": 1,
    "created": "2021-11-22T21:03:15.001000+05:00",
    "updated": "2021-11-22T21:03:15.001000+05:00" 
   },
];


const getPipeline = [
    {
        "pipeline": {
            "name": "sad",
            "roleArn": "arn:aws:iam::000111222333:role/service-role/AWSCodePipelineServiceRole-us-east-1-sad",
            "artifactStore": {
                "type": "S3",
                "location": "codepipeline-us-east-1-347340132483",
                "encryptionKey": {
                    "id": "arn:aws:kms:us-east-1:000111222333:alias/sadeed-k1",
                    "type": "KMS"
                }
            },
        }
    }

];

const listAliases = [
    {
        "AliasName": "alias/sadeed-k1",
        "AliasArn": "arn:aws:kms:us-east-1:000111222333:alias/sadeed-k1",
        "TargetKeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "CreationDate": "2021-11-15T17:05:31.308000+05:00",
        "LastUpdatedDate": "2021-11-15T17:05:31.308000+05:00"
    },
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

const createCache = (pipelines,  keys, kmsAliases, getPipeline, describeKey, pipelinesErr, kmsAliasesErr, keysErr, describeKeyErr, getPipelineErr) => {

    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    var name = (pipelines && pipelines.length) ? pipelines[0].name: null;
    return {
        codepipeline: {
            listPipelines: {
                'us-east-1': {
                    err: pipelinesErr,
                    data: pipelines
                },
            },
            getPipeline: {
                'us-east-1': {
                    [name]: {
                        data: getPipeline,
                        err: getPipelineErr
                    }
                }
            }
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    data: kmsAliases,
                    err: kmsAliasesErr
                },
            },
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

describe('pipelineArtifactsEncrypted', function () {
    describe('run', function () {
        it('should PASS if Pipeline Artifacts is encrypted with desired encryption level', function (done) {
            const cache = createCache([listPipelines[0]], listKeys, listAliases, getPipeline[0], describeKey[0]);
            pipelineArtifactsEncrypted.run(cache, { pipeline_artifacts_encryption : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Pipeline Artifacts not encrypted with desired encryption level', function (done) {
            const cache = createCache([listPipelines[0]], listKeys, listAliases, getPipeline[0], describeKey[1]);
            pipelineArtifactsEncrypted.run(cache, { pipeline_artifacts_encryption : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Pipeline Artifacts found', function (done) {
            const cache = createCache([]);
            pipelineArtifactsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Pipeline Artifacts', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Pipeline Artifacts" });
            pipelineArtifactsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listPipelines, null, null, null, { message: "Unable to list KMS keys" });
            pipelineArtifactsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})
