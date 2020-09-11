var expect = require('chai').expect;
const outputResultEncryption = require('./outputResultEncryption');

const jobs = [
    {
        "JobId": "c494f137172cadfcd8e6dd9e38e81aca",
        "JobName": "test-job",
        "JobStatus": "FAILED",
        "Message": "NO_WRITE_ACCESS_TO_OUTPUT: The provided data access role does not have write access to the output S3 URI or it does not have access to the output S3 KMS Key.",
        "SubmitTime": "2020-08-15T13:52:31.427Z",
        "EndTime": "2020-08-15T13:52:43.121Z",
        "InputDataConfig": {
          "S3Uri": "s3://public-sample-us-east-1/AsyncBatchJobs/",
          "InputFormat": "ONE_DOC_PER_LINE"
        },
        "OutputDataConfig": {
          "S3Uri": "s3://testbucketplaintext1/12345654321-NER-c494f137172cadfcd8e6dd9e38e81aca/output/output.tar.gz",
          "KmsKeyId": "arn:aws:kms:us-east-1:12345654321:key/5b65492d-1d8e-46fc-9095-08812a975fd1"
        },
        "LanguageCode": "en",
        "DataAccessRoleArn": "arn:aws:iam::12345654321:role/service-role/AmazonComprehendServiceRole-test-comprehend-role"
      },
      {
        "JobId": "83625cfc598649b886ae893d1c19d787",
        "JobName": "test-114",
        "JobStatus": "FAILED",
        "Message": "NO_WRITE_ACCESS_TO_OUTPUT: The provided data access role does not have write access to the output S3 URI.",
        "SubmitTime": "2020-08-24T19:14:31.108Z",
        "EndTime": "2020-08-24T19:14:43.044Z",
        "InputDataConfig": {
          "S3Uri": "s3://public-sample-us-east-1/AsyncBatchJobs/",
          "InputFormat": "ONE_DOC_PER_LINE"
        },
        "OutputDataConfig": {
          "S3Uri": "s3://ajkbasjhg215/entities-detection-output/12345654321-NER-83625cfc598649b886ae893d1c19d787/output/output.tar.gz"
        },
        "LanguageCode": "en",
        "DataAccessRoleArn": "arn:aws:iam::12345654321:role/service-role/AmazonComprehendServiceRole-test-comprehend-role",
        "VolumeKmsKeyId": "arn:aws:kms:us-east-1:12345654321:key/5b65492d-1d8e-46fc-9095-08812a975fd1"
      }
]

const createCache = (entitiesDetectionJobs, keyPhrasesDetectionJobs, dominantLanguageDetectionJobs, topicDetectionJobs, documentClassificationJobs, sentimentDetectionJobs) => {
    return {
        comprehend: {
            listEntitiesDetectionJobs: {
                'us-east-1': {
                    data: entitiesDetectionJobs
                },
            },
            listKeyPhrasesDetectionJobs: {
                'us-east-1': {
                    data: keyPhrasesDetectionJobs
                },
            },
            listDominantLanguageDetectionJobs: {
                'us-east-1': {
                    data: dominantLanguageDetectionJobs
                },
            },
            listTopicsDetectionJobs: {
                'us-east-1': {
                    data: topicDetectionJobs
                },
            },
            listDocumentClassificationJobs: {
                'us-east-1': {
                    data: documentClassificationJobs
                },
            },
            listSentimentDetectionJobs: {
                'us-east-1': {
                    data: sentimentDetectionJobs
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        comprehend: {
            listEntitiesDetectionJobs: {
                'us-east-1': {
                    err: {
                        message: 'error describing entites detection jobs'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        comprehend: {
            listEntitiesDetectionJobs: {
                'us-east-1': null,
            },
        },
    };
};

describe('outputResultEncryption', function () {
    describe('run', function () {
        it('should PASS if ouput result encryption is enabled for comprehend job', function (done) {
            const cache = createCache([jobs[0]]);
            outputResultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(6);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if ouput result encryption is not enabled for comprehend job', function (done) {
            const cache = createCache([jobs[1]]);
            outputResultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(6);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no comprehend jobs found', function (done) {
            const cache = createCache([]);
            outputResultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(6);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was error listing comprehend jobs', function (done) {
            const cache = createErrorCache();
            outputResultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for comprehend jobs', function (done) {
            const cache = createNullCache();
            outputResultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
