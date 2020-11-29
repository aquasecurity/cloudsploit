var expect = require('chai').expect;
var cloudtrailEncryption = require('./cloudtrailEncryption');

const trails = [
    {
        "Name": "trail-1",
        "S3BucketName": "cloudtrail-bucket",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456654321:trail/trail-1",
        "LogFileValidationEnabled": true,
        "KmsKeyId": "a14dea26-1459-4f62-ab85-d5a54293a495",
        "HasCustomEventSelectors": true,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    },
    {
        "Name": "trail-2",
        "S3BucketName": "aws-cloudtrail-logs-123456654321-test-events-690d8af2",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": false,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456654321:trail/trail-2",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    }
];

const createCache = (trails) => {
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    data: trails,
                },
            }
        },
    };
};

const createErrorCache = (trails) => {
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    err: {
                        message: 'error describing trails'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': null,
            },
        },
    };
};

describe('cloudtrailEncryption', function () {
    describe('run', function () {
        it('should PASS if CloudTrail encryption is enabled', function (done) {
            const cache = createCache([trails[0]]);
            cloudtrailEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if CloudTrail encryption is not enabled', function (done) {
            const cache = createCache([trails[1]]);
            cloudtrailEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if no CloudTrail is not enabled', function (done) {
            const cache = createCache([]);
            cloudtrailEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to query for trails', function (done) {
            const cache = createErrorCache();
            cloudtrailEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if describe CloudTrail response not found', function (done) {
            const cache = createNullCache();
            cloudtrailEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
