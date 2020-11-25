var expect = require('chai').expect;
const cloudtrailS3Bucket = require('./cloudtrailS3Bucket');

const describeTrails = [
    {
        "Name": "management-events",
        "S3BucketName": "aws-cloudtrail-logs-119d2f9a",
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

const createCache = (trail, status) => {
    return {
        cloudtrail:{
            describeTrails: {
                'us-east-1': {
                    data: trail
                },
            }
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
        }
    };
};

const createNullCache = () => {
    return {
        cloudtrail:{
            describeTrails: {
                'us-east-1': null,
            }
        }
    };
};

describe('cloudtrailS3Bucket', function () {
    describe('run', function () {
        it('should PASS if CloudTrail trail has correct S3 bucket configured', function (done) {
            const cache = createCache([describeTrails[0]]);
            cloudtrailS3Bucket.run(cache, { trail_s3_bucket_name: 'aws-cloudtrail-logs-119d2f9a' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if CloudTrail trail does not have correct S3 bucket configured', function (done) {
            const cache = createCache([describeTrails[0]]);
            cloudtrailS3Bucket.run(cache, { trail_s3_bucket_name: 'sample-bucket-123' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if CloudTrail is not enabled', function (done) {
            const cache = createCache([]);
            cloudtrailS3Bucket.run(cache, { trail_s3_bucket_name: 'sample-bucket-123' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to describe CloudTrail trails', function (done) {
            const cache = createErrorCache();
            cloudtrailS3Bucket.run(cache, { trail_s3_bucket_name: 'sample-bucket-123' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe CloudTrail trails response not found', function (done) {
            const cache = createNullCache();
            cloudtrailS3Bucket.run(cache, { trail_s3_bucket_name: 'sample-bucket-123' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should not return anything if S3 bucket name is not provided in settings', function (done) {
            const cache = createNullCache();
            cloudtrailS3Bucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
