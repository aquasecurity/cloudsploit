var expect = require('chai').expect;
var translateJobOutputEncrypted = require('./translateJobOutputEncrypted');

const listTextTranslationJobs = [
    {
        "JobId": "03c3e7dea26241b22bcbc48624beb75f",
        "JobName": "aqua-job1",
        "JobStatus": "IN_PROGRESS",
        "JobDetails": {
          "TranslatedDocumentsCount": 0,
          "DocumentsWithErrorsCount": 0,
          "InputDocumentsCount": 1
        },
        "SourceLanguageCode": "en",
        "TargetLanguageCodes": [
          "ar"
        ],
        "SubmittedTime": "2021-11-11T12:50:47.661Z",
        "InputDataConfig": {
          "S3Uri": "s3://aquawebsite/data/",
          "ContentType": "text/plain"
        },
        "OutputDataConfig": {
          "S3Uri": "s3://aquawebsite/data1/000011112222-TranslateText-03c3e7dea26241b22bcbc48624beb75f/",
          "EncryptionKey": {
            "Type": "KMS",
            "Id": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
          }
        },
        "DataAccessRoleArn": "arn:aws:iam::000011112222:role/service-role/AmazonTranslateServiceRole-translate"
    },
    {
        "JobId": "03c3e7dea26241b22bcbc48624beb75f",
        "JobName": "aqua-job1",
        "JobStatus": "IN_PROGRESS",
        "JobDetails": {
          "TranslatedDocumentsCount": 0,
          "DocumentsWithErrorsCount": 0,
          "InputDocumentsCount": 1
        },
        "SourceLanguageCode": "en",
        "TargetLanguageCodes": [
          "ar"
        ],
        "SubmittedTime": "2021-11-11T12:50:47.661Z",
        "InputDataConfig": {
          "S3Uri": "s3://aquawebsite/data/",
          "ContentType": "text/plain"
        },
        "OutputDataConfig": {
          "S3Uri": "s3://aquawebsite/data1/000011112222-TranslateText-03c3e7dea26241b22bcbc48624beb75f/",
        },
        "DataAccessRoleArn": "arn:aws:iam::000011112222:role/service-role/AmazonTranslateServiceRole-translate"
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
        translate: {
            listTextTranslationJobs: {
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

describe('translateJobOutputEncrypted', function () {
    describe('run', function () {
        it('should PASS if Translate job is encrypted with desired encryption level', function (done) {
            const cache = createCache([listTextTranslationJobs[0]], listKeys, describeKey[0]);
            translateJobOutputEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Translate job is not encrypted with desired encryption level', function (done) {
            const cache = createCache([listTextTranslationJobs[1]], listKeys);
            translateJobOutputEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Translate jobs found', function (done) {
            const cache = createCache([]);
            translateJobOutputEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Translate jobs', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Translate jobs" });
            translateJobOutputEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listTextTranslationJobs, null, null, null, { message: "Unable to list KMS keys" });
            translateJobOutputEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})