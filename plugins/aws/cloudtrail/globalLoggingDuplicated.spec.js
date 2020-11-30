var expect = require('chai').expect;
const globalLoggingDuplicated = require('./globalLoggingDuplicated');

const describeTrails = [
    {
        "Name": "management-events",
        "S3BucketName": "aws-cloudtrail-logs-111122223333-119d2f9a",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:111122223333:trail/management-events",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    },
    {
        "Name": "management-events",
        "S3BucketName": "aws-cloudtrail-logs-111122223333-119d2f9a",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:111122223333:trail/management-events",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    },
    {
        "Name": "management-events",
        "S3BucketName": "aws-cloudtrail-logs-111122223333-119d2f9a",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:111122223333:trail/management-events2",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    },
    {
        "Name": "management-events",
        "S3BucketName": "aws-cloudtrail-logs-111122223333-119d2f9a",
        "IncludeGlobalServiceEvents": false,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:111122223333:trail/management-events2",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    }
];

const createCache = (trails) => {
    return {
        cloudtrail:{
            describeTrails: {
                'us-east-1': {
                    data: trails
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        cloudtrail:{
            describeTrails: {
                'us-east-1': {
                    err: {
                        message: 'error describing CloudTrail trails'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        cloudtrail:{
            describeTrails: {
                'us-east-1': null,
            },
        },
    };
};

describe('globalLoggingDuplicated', function () {
    describe('run', function () {
            it('should PASS if CloudTrail global services event logs are not being duplicated', function (done) {
            const cache = createCache([describeTrails[0]]);
            globalLoggingDuplicated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if CloudTrail global services event logging is not enabled', function (done) {
            const cache = createCache([describeTrails[0], describeTrails[2]]);
            globalLoggingDuplicated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if CloudTrail global services event logs are being duplicated', function (done) {
            const cache = createCache([describeTrails[3]]);
            globalLoggingDuplicated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if CloudTrail is not enabled', function (done) {
            const cache = createCache([]);
            globalLoggingDuplicated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to describe CloudTrail trails', function (done) {
            const cache = createErrorCache();
            globalLoggingDuplicated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
        