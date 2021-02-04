var expect = require('chai').expect;
const cloudtrailManagementEvents = require('./cloudtrailManagementEvents');

const describeTrails = [
    {
        "Name": "test-trail",
        "S3BucketName": "test-bucket-ct-1",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:112233445566:trail/test-trail",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    },
    {
        "Name": "test-trail-1",
        "S3BucketName": "test-bucket-ct",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:112233445566:trail/test-trail-1",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    }
];

const getEventSelectors = [
    {
        "TrailARN": "arn:aws:cloudtrail:us-east-1:112233445566:trail/test-trail",
        "EventSelectors": [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": true,
                "DataResources": [
                    {
                        "Type": "AWS::S3::Object",
                        "Values": [
                            "arn:aws:s3"
                        ]
                    }
                ],
                "ExcludeManagementEventSources": []
            }
        ]
    },
    {
        "TrailARN": "arn:aws:cloudtrail:us-east-1:112233445566:trail/test-trail-1",
        "EventSelectors": [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": false,
                "DataResources": [],
                "ExcludeManagementEventSources": []
            }
        ]
    }
];

const createCache = (describeTrails, getEventSelectors, describeTrailsErr, getEventSelectorsErr) => {
    var trailARN = (describeTrails && describeTrails.length) ? describeTrails[0].TrailARN : null;
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    err: describeTrailsErr,
                    data: describeTrails
                }
            },
            getEventSelectors: {
                'us-east-1': {
                    [trailARN]: {
                        err: getEventSelectorsErr,
                        data: getEventSelectors
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': null
            }
        }
    };
};

describe('cloudtrailManagementEvents', function () {
    describe('run', function () {
        it('should PASS if CloudTrail trail is configured to log management events', function (done) {
            const cache = createCache([describeTrails[0]], getEventSelectors[0]);
            cloudtrailManagementEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if CloudTrail trail is not configured to log management events', function (done) {
            const cache = createCache([describeTrails[1]], getEventSelectors[1]);
            cloudtrailManagementEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if CloudTrail is not enabled', function (done) {
            const cache = createCache([]);
            cloudtrailManagementEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for trails', function (done) {
            const cache = createCache(null, null, { message: "Unable to describe trails" }, null);
            cloudtrailManagementEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for event selectors', function (done) {
            const cache = createCache([describeTrails[0]], getEventSelectors[0], null, { message: "Unable to get event selectors" });
            cloudtrailManagementEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return any results describe trails response not found', function (done) {
            const cache = createNullCache();
            cloudtrailManagementEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
