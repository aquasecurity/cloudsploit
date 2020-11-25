var expect = require('chai').expect;
var cloudtrailToCloudwatch = require('./cloudtrailToCloudwatch');

const trails = [
    {
        "Name": "trail-1",
        "S3BucketName": "cloudtrail-bucket",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456654321:trail/trail-1",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": true,
        "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:112233445566:log-group:aws-cloudtrail-logs-112233445566-5f8a5d87:*",
        "CloudWatchLogsRoleArn": "arn:aws:iam::112233445566:role/service-role/CloudTrailCloudwatchRole",
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

describe('cloudtrailToCloudwatch', function () {
    describe('run', function () {
        it('should PASS if CloudTrail CloudWatch integration is enabled', function (done) {
            const cache = createCache([trails[0]]);
            cloudtrailToCloudwatch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if CloudTrail CloudWatch integration is not enabled', function (done) {
            const cache = createCache([trails[1]]);
            cloudtrailToCloudwatch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if no CloudTrail is not enabled', function (done) {
            const cache = createCache([]);
            cloudtrailToCloudwatch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to query for trails', function (done) {
            const cache = createErrorCache();
            cloudtrailToCloudwatch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if describe CloudTrail response not found', function (done) {
            const cache = createNullCache();
            cloudtrailToCloudwatch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
