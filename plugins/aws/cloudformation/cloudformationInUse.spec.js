var expect = require('chai').expect;
var cloudformationInUse = require('./cloudformationInUse');

const describeStacks = [
    {
        "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/sam-app/e26f50d0-6efd-11ec-bb7d-0e5217d78663",
        "StackName": "sam-app",
        "ChangeSetId": "arn:aws:cloudformation:us-east-1:000011112222:changeSet/samcli-deploy1641479723/70df5351-0c36-4f77-bf41-fe5fe49c4a3a",
        "Description": "S3 Uploader - sample application",
        "CreationTime": "2022-01-06T14:35:24.796000+00:00",
        "LastUpdatedTime": "2022-01-06T14:35:52.880000+00:00",
        "RollbackConfiguration": {},
        "StackStatus": "CREATE_COMPLETE",
        "DisableRollback": true,
        "NotificationARNs": [],
        "Capabilities": [
            "CAPABILITY_IAM"
        ],
        "Outputs": [
            {
                "OutputKey": "APIendpoint",
                "OutputValue": "https://m9kyzunubc.execute-api.us-east-1.amazonaws.com",
                "Description": "HTTP API endpoint URL"
            },
            {
                "OutputKey": "S3UploadBucketName",
                "OutputValue": "sam-app-s3uploadbucket-ylnxiraqgwuq",
                "Description": "S3 bucket for application uploads"
            }
        ],
        "Tags": [],
        "DriftInformation": {
            "StackDriftStatus": "NOT_CHECKED"
        }
    },
    {}
];



const createCache = (describeStacks, describeStacksErr) => { 
    return {
        cloudformation: {
            describeStacks: {
                'us-east-1': {
                    err: describeStacksErr,
                    data: describeStacks
                },
            },
        },
    };
};

describe('cloudformationInUse', function () {
    describe('run', function () {
        it('should PASS if Amazon CloudFormation service is currently in use', function (done) {
            const cache = createCache([describeStacks[0]]);
            cloudformationInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('CloudFormation service is being used');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Amazon CloudFormation service is not currently in use', function (done) {
            const cache = createCache(describeStacks[1]);
            cloudformationInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('CloudFormation service is not being used');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if Unable to query CloudFormation stacks', function (done) {
            const cache = createCache(null, { message: "Unable to query CloudFormation stacks" });
            cloudformationInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query CloudFormation stacks');
                done();
            });
        });
    });
}); 