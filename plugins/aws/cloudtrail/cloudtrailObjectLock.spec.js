var expect = require('chai').expect;
var cloudtrailObjectLock = require('./cloudtrailObjectLock');

const trails = [
    {
        "Name": "akhtar-ct3-57",
        "S3BucketName": "akhtar-cloudtrail-bucket",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456654321:trail/akhtar-ct3-57",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": true,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    },
    {
        "Name": "akhtar-ct2-57",
        "S3BucketName": "aws-cloudtrail-logs-123456654321-test-events-690d8af2",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": false,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456654321:trail/akhtar-ct2-57",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    }
];

const bucketObjectLockConfigurations = [
    {
        ObjectLockEnabled: 'Enabled' ,
        Rule: {
            DefaultRetention: {
                Mode: 'GOVERNANCE',
                Days: 1
            }
        }
    }
];

const createCache = (trails, bucketObjectLockConfigurations) => {
    if (trails && trails.length) var s3BucketName = trails[0].S3BucketName;
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    data: trails,
                },
            }
        },
        s3: {
            getObjectLockConfiguration: {
                'us-east-1': {
                    [s3BucketName]: {
                        data: {
                            ObjectLockConfiguration: bucketObjectLockConfigurations
                        }
                    }
                }
            }
        }
    };
};

const createErrorCache = (trails) => {
    if (trails && trails.length) {
        var s3BucketName = trails[0].S3BucketName
        return {
            cloudtrail: {
                describeTrails: {
                    'us-east-1': {
                        data: trails,
                    },
                }
            },
            s3: {
                getObjectLockConfiguration: {
                    'us-east-1': {
                        [s3BucketName]: {
                            err: {
                                code: 'ObjectLockConfigurationNotFoundError'
                            }
                        }
                    }
                }
            }
        }
    }
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

describe('cloudtrailObjectLock', function () {
    describe('run', function () {
        it('should PASS if object lock is enabled for s3 bucket', function (done) {
            const cache = createCache([trails[0]], bucketObjectLockConfigurations[0]);
            cloudtrailObjectLock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if object lock configuration does not exist for s3 bucket', function (done) {
            const cache = createErrorCache([trails[1]]);
            cloudtrailObjectLock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if CloudTrail is not enabled', function (done) {
            const cache = createCache([]);
            cloudtrailObjectLock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for trails', function (done) {
            const cache = createErrorCache();
            cloudtrailObjectLock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for trails', function (done) {
            const cache = createNullCache();
            cloudtrailObjectLock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
