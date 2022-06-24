var expect = require('chai').expect;
var databrewJobOutputEncrypted = require('./databrewJobOutputEncrypted');

const listJobs = [
    {
        "AccountId": "000011112222",
        "CreatedBy": "arn:aws:iam::000011112222:root",
        "CreateDate": "2021-11-15T15:46:11.255Z",
        "DatasetName": "sample-ds",
        "EncryptionKeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
        "EncryptionMode": "SSE-KMS",
        "Name": "aqua-job",
        "Type": "RECIPE",
        "LastModifiedBy": null,
        "LastModifiedDate": null,
        "LogSubscription": "DISABLE",
        "MaxCapacity": 5,
        "MaxRetries": 0,
        "Outputs": [
          {
            "CompressionFormat": null,
            "Format": "CSV",
            "Location": {
              "Bucket": "aqua-data-bucket",
              "Key": null
            },
            "Overwrite": false,
            "FormatOptions": {
              "Csv": {
                "Delimiter": ","
              }
            }
          }
        ],
        "ProjectName": null,
        "RecipeReference": {
          "Name": "sample-recipe",
          "RecipeVersion": "1.0"
        },
        "ResourceArn": "arn:aws:databrew:us-east-1:000011112222:job/aqua-job",
        "RoleArn": "arn:aws:iam::000011112222:role/service-role/AWSGlueDataBrewServiceRole-databrew-role",
        "Timeout": 2880,
        "Tags": {}
    },
    {
        "AccountId": "000011112222",
        "CreatedBy": "arn:aws:iam::000011112222:root",
        "CreateDate": "2021-11-15T16:06:58.027Z",
        "DatasetName": "sample-ds",
        "EncryptionKeyArn": null,
        "EncryptionMode": null,
        "Name": "aqua-job2",
        "Type": "RECIPE",
        "LastModifiedBy": null,
        "LastModifiedDate": null,
        "LogSubscription": "DISABLE",
        "MaxCapacity": 5,
        "MaxRetries": 0,
        "Outputs": [
          {
            "CompressionFormat": null,
            "Format": "CSV",
            "Location": {
              "Bucket": "aqua-data-bucket",
              "Key": null
            },
            "Overwrite": false,
            "FormatOptions": {
              "Csv": {
                "Delimiter": ","
              }
            }
          }
        ],
        "ProjectName": null,
        "RecipeReference": {
          "Name": "sample-recipe",
          "RecipeVersion": "1.0"
        },
        "ResourceArn": "arn:aws:databrew:us-east-1:000011112222:job/aqua-job2",
        "RoleArn": "arn:aws:iam::000011112222:role/service-role/AWSGlueDataBrewServiceRole-databrew-role",
        "Timeout": 2880,
        "Tags": {}
    },
    {
        "AccountId": "000011112222",
        "CreatedBy": "arn:aws:iam::000011112222:root",
        "CreateDate": "2021-11-15T16:18:29.930Z",
        "DatasetName": "sample-ds",
        "EncryptionKeyArn": null,
        "EncryptionMode": "SSE-S3",
        "Name": "aqua-job3",
        "Type": "RECIPE",
        "LastModifiedBy": null,
        "LastModifiedDate": null,
        "LogSubscription": "DISABLE",
        "MaxCapacity": 5,
        "MaxRetries": 0,
        "Outputs": [
          {
            "CompressionFormat": null,
            "Format": "CSV",
            "Location": {
              "Bucket": "aqua-data-bucket",
              "Key": null
            },
            "Overwrite": false,
            "FormatOptions": {
              "Csv": {
                "Delimiter": ","
              }
            }
          }
        ],
        "ProjectName": null,
        "RecipeReference": {
          "Name": "sample-recipe",
          "RecipeVersion": "1.0"
        },
        "ResourceArn": "arn:aws:databrew:us-east-1:000011112222:job/aqua-job3",
        "RoleArn": "arn:aws:iam::000011112222:role/service-role/AWSGlueDataBrewServiceRole-databrew-role",
        "Timeout": 2880,
        "Tags": {}
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

const createCache = (jobs, keys, describeKey, jobsErr, keysErr, describeKeyErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyArn.split('/')[1] : null;
    return {
        databrew: {
            listJobs: {
                'us-east-1': {
                    err: jobsErr,
                    data: jobs
                },
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

describe('databrewJobOutputEncrypted', function () {
    describe('run', function () {
        it('should PASS if DataBrew job is encrypted with desired encryption level', function (done) {
            const cache = createCache([listJobs[0]], listKeys, describeKey[0]);
            databrewJobOutputEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if DataBrew job is not encrypted with desired encryption level', function (done) {
            const cache = createCache([listJobs[1]], listKeys);
            databrewJobOutputEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no DataBrew jobs found', function (done) {
            const cache = createCache([]);
            databrewJobOutputEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Translate jobs', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Translate jobs" });
            databrewJobOutputEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listJobs, null, null, null, { message: "Unable to list KMS keys" });
            databrewJobOutputEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})