var expect = require('chai').expect;
const cloudtrailDeliveryFailing = require('./cloudtrailDeliveryFailing');

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
        "IsLogging": true,
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
];


const createCache = (trail, status) => {
    if (trail && trail.length) var trailArn = trail[0].TrailARN;

    return {
        cloudtrail:{
            describeTrails: {
                'us-east-1': {
                    data: trail
                },
            },
            getTrailStatus: {
                'us-east-1': {
                    [trailArn]: {
                        data: status
                    },
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
            },
            getTrailStatus: {
                'us-east-1': {
                    err: {
                        message: 'error getting CloudTrail trail status'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        cloudtrail:{
            describeTrails: {
                'us-east-1': null,
            },
            getTrailStatus: {
                'us-east-1': null,
            },
        },
    };
};

describe('cloudtrailDeliveryFailing', function () {
    describe('run', function () {
        it('should PASS if logs for CloudTrail trail are being delivered', function (done) {
            const cache = createCache([describeTrails[0]], getTrailStatus[0]);
            cloudtrailDeliveryFailing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if logs for CloudTrail trail are not being delivered', function (done) {
            const cache = createCache([describeTrails[0]], getTrailStatus[1]);
            cloudtrailDeliveryFailing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if CloudTrail is not enabled', function (done) {
            const cache = createCache([]);
            cloudtrailDeliveryFailing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to describe CloudTrail trails', function (done) {
            const cache = createErrorCache();
            cloudtrailDeliveryFailing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to get CloudTrail trail status', function (done) {
            const cache = createCache([describeTrails[0]]);
            cloudtrailDeliveryFailing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe CloudTrail trails response not found', function (done) {
            const cache = createNullCache();
            cloudtrailDeliveryFailing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
