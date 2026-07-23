var expect = require('chai').expect;
var cloudtrailEnabled = require('./cloudtrailEnabled');

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
    },
    {
        "Name": "trail-3",
        "S3BucketName": "aws-cloudtrail-logs-123456654321-test-events-690d8af2",
        "IncludeGlobalServiceEvents": false,
        "IsMultiRegionTrail": false,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456654321:trail/trail-3",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    }
];

const getTrailStatus = [
    {
        "IsLogging": true,
        "LatestDeliveryTime": 1604522848.468,
        "StartLoggingTime": 1604521222.552,
        "LatestDeliveryAttemptTime": "2020-11-04T20:47:28Z",
        "LatestNotificationAttemptTime": "",
        "LatestNotificationAttemptSucceeded": "",
        "LatestDeliveryAttemptSucceeded": "2020-11-04T20:47:28Z",
        "TimeLoggingStarted": "2020-11-04T20:20:22Z",
        "TimeLoggingStopped": ""
    },
    {
        "IsLogging": false,
        "LatestDeliveryTime": 1604522848.468,
        "StartLoggingTime": 1604521222.552,
        "LatestDeliveryError": "NoSuchBucket",
        "LatestDeliveryAttemptTime": "2020-11-04T20:47:28Z",
        "LatestNotificationAttemptTime": "",
        "LatestNotificationAttemptSucceeded": "",
        "LatestDeliveryAttemptSucceeded": "2020-11-04T20:47:28Z",
        "TimeLoggingStarted": "2020-11-04T20:20:22Z",
        "TimeLoggingStopped": ""
    }
]

const createCache = (trails, getTrailStatus) => {
    var trailARN = (trails && trails.length) ? trails[0].TrailARN : null;
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    data: trails,
                },
            },
            getTrailStatus: {
                'us-east-1': {
                    [trailARN]: {
                        data: getTrailStatus
                    }
                }
            }
        }
    };
};

const createErrorCache = (trails) => {
    var trailARN = (trails && trails.length) ? trails[0].TrailARN : null;
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    err: {
                        message: 'error describing trails'
                    },
                },
            },
            getTrailStatus: {
                'us-east-1': {
                    [trailARN]: {
                        err: {
                            message: 'error getting trail status'
                        }
                    }
                }
            }
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

describe('cloudtrailEnabled', function () {
    describe('run', function () {
        it('should PASS if CloudTrail is enabled and monitoring regional and global services', function (done) {
            const cache = createCache([trails[0]], getTrailStatus[0]);
            cloudtrailEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if CloudTrail is configured and enabled to monitor global services', function (done) {
            const cache = createCache([trails[0]], getTrailStatus[0]);
            cloudtrailEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should PASS if CloudTrail is enabled and monitoring regional services', function (done) {
            const cache = createCache([trails[2]], getTrailStatus[0]);
            cloudtrailEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if CloudTrail is configured for regional monitoring but is not logging API calls', function (done) {
            const cache = createCache([trails[0]], getTrailStatus[1]);
            cloudtrailEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if CloudTrail is configured for regional monitoring but is not logging API calls', function (done) {
            const cache = createCache([trails[0]], getTrailStatus[1]);
            cloudtrailEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if CloudTrail is not enabled', function (done) {
            const cache = createCache([]);
            cloudtrailEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if CloudTrail is not configured to monitor global services', function (done) {
            const cache = createCache([trails[2]], getTrailStatus[1]);
            cloudtrailEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to query for trails', function (done) {
            const cache = createErrorCache();
            cloudtrailEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
