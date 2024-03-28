var expect = require('chai').expect;
var cloudFormationDeletionPolicy = require('./cloudformationDeletionPolicy');

const createCache = (stacks, templates) => {
    return {
        cloudformation: {
            listStacks: {
                'us-east-1': {
                    err: null,
                    data: stacks
                }
            },
            getTemplate: templates.reduce((acc, template, index) => {
                acc['us-east-1'] = acc['us-east-1'] || {};
                acc['us-east-1'][stacks[index].StackName] = {
                    err: null,
                    data: template
                };
                return acc;
            }, {})
        }
    };
};

describe('CloudFormation Deletion Policy in Use', function () {
    describe('run', function () {
        it('should return unknown result if unable to list the CloudFormation stacks', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for CloudFormation stacks');
                done();
            };

            const cache = createCache(null, []);

            cloudFormationDeletionPolicy.run(cache, {}, callback);
        });

        it('should return passing result if no CloudFormation stacks found in region', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No CloudFormation stacks found');
                done();
            };

            const cache = createCache([], []);

            cloudFormationDeletionPolicy.run(cache, {}, callback);
        });

        it('should return passing result if deletion policy is used for CloudFormation stack', function (done) {
            const stacks = [
                {
                    "StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
                    "StackName": "AKD",
                    "CreationTime": "2020-12-05T19:49:48.498000+00:00",
                    "StackStatus": "CREATE_COMPLETE",
                }
            ];

            const templates = [
                {
                    "ResponseMetadata": {
                        "RequestId": "ba242bd7b841-a7fa-4229xa00-4t2-4294",
                    },
                    "TemplateBody": "{\"AWSTemplateFormatVersion\":\"2010-09-09\",\"Description\":\"The AWS CloudFormation template for this Serverless application\",\"Resources\":{\"ServerlessDeploymentBucket\":{\"Type\":\"AWS::S3::Bucket\",\"Properties\":{\"BucketEncryption\":{\"ServerSideEncryptionConfiguration\":[{\"ServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}},\"DeletionPolicy\":\"Retain\",\"Properties\":{\"FunctionName\":{\"Ref\":\"testfunction\"}}}}}",
                    "StagesAvailable": [
                        "Original",
                        "Processed"
                    ]
                }
            ];

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Deletion Policy is used for CloudFormation stack ');
                done();
            };

            const cache = createCache(stacks, templates);

            cloudFormationDeletionPolicy.run(cache, {}, callback);
        });

        it('should return failing result if deletion policy is not used for CloudFormation stack', function (done) {
            const stacks = [
                {
                    "StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
                    "StackName": "AKD",
                    "CreationTime": "2020-12-05T19:49:48.498000+00:00",
                    "StackStatus": "CREATE_COMPLETE",
                }
            ];

            const templates = [
                {
                    "ResponseMetadata": {
                        "RequestId": "ba242bd7b841-a7fa-4229xa00-4t2-4294",
                    },
                    "TemplateBody": "{\"AWSTemplateFormatVersion\":\"2010-09-09\",\"Description\":\"The AWS CloudFormation template for this Serverless application\",\"Resources\":{\"ServerlessDeploymentBucket\":{\"Type\":\"AWS::S3::Bucket\",\"Properties\":{\"BucketEncryption\":{\"ServerSideEncryptionConfiguration\":[{\"ServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}},\"Properties\":{\"FunctionName\":{\"Ref\":\"testfunction\"}}}}}",
                    "StagesAvailable": [
                        "Original",
                        "Processed"
                    ]
                }
            ];

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Deletion Policy is not used for CloudFormation stack ');
                done();
            };

            const cache = createCache(stacks, templates);

            cloudFormationDeletionPolicy.run(cache, {}, callback);
        });

    });
});
