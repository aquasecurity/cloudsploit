var expect = require('chai').expect;
var pipelineDataEncrypted = require('./pipelineDataEncrypted');

const listPipelines = [
    {
        "Id": "1636527154039-wkwqg1",
        "Arn": "arn:aws:elastictranscoder:us-east-1:000011112222:pipeline/1636527154039-wkwqg1",
        "Name": "aqua-pipeline",
        "Status": "Active",
        "InputBucket": "aquabucket",
        "OutputBucket": "aquabucket",
        "Role": "arn:aws:iam::000011112222:role/Elastic_Transcoder_Default_Role",
        "AwsKmsKeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
        "Notifications": {
            "Progressing": "",
            "Completed": "",
            "Warning": "",
            "Error": ""
        },
        "ContentConfig": {
            "Bucket": "aquabucket",
            "StorageClass": "Standard",
            "Permissions": [
                {
                    "GranteeType": "Canonical",
                    "Grantee": "000011112222",
                    "Access": [
                        "Read",
                        "ReadAcp",
                        "WriteAcp",
                        "FullControl"
                    ]
                }
            ]
        },
        "ThumbnailConfig": {
            "Bucket": "aquabucket",
            "StorageClass": "Standard",
            "Permissions": [
                {
                    "GranteeType": "Canonical",
                    "Grantee": "000011112222",
                    "Access": [
                        "Read",
                        "ReadAcp",
                        "WriteAcp",
                        "FullControl"
                    ]
                }
            ]
        }
    },
    {
        "Id": "1636527154039-wkwqg1",
        "Arn": "arn:aws:elastictranscoder:us-east-1:000011112222:pipeline/1636527154039-wkwqg1",
        "Name": "aqua-pipeline",
        "Status": "Active",
        "InputBucket": "aquabucket",
        "OutputBucket": "aquabucket",
        "Role": "arn:aws:iam::000011112222:role/Elastic_Transcoder_Default_Role",
        "Notifications": {
            "Progressing": "",
            "Completed": "",
            "Warning": "",
            "Error": ""
        },
        "ContentConfig": {
            "Bucket": "aquabucket",
            "StorageClass": "Standard",
            "Permissions": [
                {
                    "GranteeType": "Canonical",
                    "Grantee": "000011112222",
                    "Access": [
                        "Read",
                        "ReadAcp",
                        "WriteAcp",
                        "FullControl"
                    ]
                }
            ]
        },
        "ThumbnailConfig": {
            "Bucket": "aquabucket",
            "StorageClass": "Standard",
            "Permissions": [
                {
                    "GranteeType": "Canonical",
                    "Grantee": "000011112222",
                    "Access": [
                        "Read",
                        "ReadAcp",
                        "WriteAcp",
                        "FullControl"
                    ]
                }
            ]
        }
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
    }
];

const listKeys = [
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
    }
]

const createCache = (pipelines, keys, describeKey, pipelinesErr, keysErr, describeKeyErr) => {
    var keyId = (pipelines && pipelines.length && pipelines[0].AwsKmsKeyArn) ? pipelines[0].AwsKmsKeyArn.split('/')[1] : null;
    return {
        elastictranscoder: {
            listPipelines: {
                'us-east-1': {
                    err: pipelinesErr,
                    data: pipelines
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

describe('pipelineDataEncrypted', function () {
    describe('run', function () {
        it('should PASS if Elastic Transcoder pipeline is encrypted with desired encryption level', function (done) {
            const cache = createCache([listPipelines[0]], listKeys, describeKey[0]);
            pipelineDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Elastic Transcoder pipeline is not encrypted with desired encyption level', function (done) {
            const cache = createCache([listPipelines[1]], listKeys, describeKey[0]);
            pipelineDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Elastic Transcoder pipelines found', function (done) {
            const cache = createCache([]);
            pipelineDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Elastic Transcoder pipelines', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Elastic Transcoder pipelines" });
            pipelineDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listPipelines, null, null, null, { message: "Unable to list KMS keys" });
            pipelineDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});