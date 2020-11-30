var expect = require('chai').expect;
const cloudtrailDataEvents = require('./cloudtrailDataEvents');

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
                "IncludeManagementEvents": true,
                "DataResources": [],
                "ExcludeManagementEventSources": []
            }
        ]
    }
];

const createCache = (trails, getEventSelectors) => {
    var trailArn = (trails && trails.length) ? trails[0].TrailARN : null;
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    data: trails,
                },
            },
            getEventSelectors: {
                'us-east-1': {
                    [trailArn]: {
                        data: getEventSelectors
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    err: {
                        message: 'error describing CloudTrail trails'
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

describe('cloudtrailDataEvents', function () {
    describe('run', function () {
        it('should PASS if CloudTrail trail has data events configured', function (done) {
            const cache = createCache([describeTrails[0]], getEventSelectors[0]);
            cloudtrailDataEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if CloudTrail trail does not have data events configured', function (done) {
            const cache = createCache([describeTrails[1]], getEventSelectors[1]);
            cloudtrailDataEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no CloudTrail trails found', function (done) {
            const cache = createCache([]);
            cloudtrailDataEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query trails', function (done) {
            const cache = createErrorCache();
            cloudtrailDataEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results describe trail response not found', function (done) {
            const cache = createNullCache();
            cloudtrailDataEvents.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
