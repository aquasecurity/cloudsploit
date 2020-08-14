var assert = require('assert');
var expect = require('chai').expect;
var eks = require('./cloudtrailBucketAccessLogging');  // TODO everything is just copied over, need to rehaul
const createCache = (descTrailsData, getBuckLogData, listBuckData, buckName) => {
    let to_return = {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    data: descTrailsData
                }
            },
        },
        s3: {
            getBucketLogging: {
                'us-east-1': {}
            },
            listBuckets: {
                'us-east-1': {
                    data: listBuckData
                }
            },
        }
    };
    to_return.s3.getBucketLogging['us-east-1'][buckName] = getBuckLogData;
    return to_return
};

describe('cloudtrailBucketAccessLogging', function () {
    describe('run', function () {
        it('should PASS if CloudTrail logging bucket has access logging enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            };

            const cache = createCache(
                [
                    {
                        "Name": "delete-me-ms",
                        "S3BucketName": "delete-me-ueoeuaou-ms",
                        "IncludeGlobalServiceEvents": true,
                        "IsMultiRegionTrail": true,
                        "HomeRegion": "us-east-1",
                        "TrailARN": "arn:aws:cloudtrail:us-east-1:000000000000:trail/delete-me-ms",
                        "LogFileValidationEnabled": true,
                        "HasCustomEventSelectors": true,
                        "HasInsightSelectors": false,
                        "IsOrganizationTrail": false
                    },
                ],
                {
                  data: {
                    "LoggingEnabled": {
                        "TargetPrefix": "foo",
                        "TargetBucket": "delete-me-ueoeuaou-ms"
                    }
                },
                },
                [
                    {
                        "Name": "delete-me-ueoeuaou-ms",
                        "CreationDate": "2020-06-30T14:29:53.000Z"
                    },
                ],
                'delete-me-ueoeuaou-ms'
            );

            eks.run(cache, {}, callback);
        });

        it('should WARN if CloudTrail logging bucket has access logging disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            };

            const cache = createCache(
                [
                    {
                        "Name": "delete-me-ms",
                        "S3BucketName": "delete-me-ueoeuaou-ms",
                        "IncludeGlobalServiceEvents": true,
                        "IsMultiRegionTrail": true,
                        "HomeRegion": "us-east-1",
                        "TrailARN": "arn:aws:cloudtrail:us-east-1:000000000000:trail/delete-me-ms",
                        "LogFileValidationEnabled": true,
                        "HasCustomEventSelectors": true,
                        "HasInsightSelectors": false,
                        "IsOrganizationTrail": false
                    },
                ],
                {
                    data: {},
                },
                [
                    {
                        "Name": "delete-me-ueoeuaou-ms",
                        "CreationDate": "2020-06-30T14:29:53.000Z"
                    },
                ],
                'delete-me-ueoeuaou-ms'
            );

            eks.run(cache, {}, callback);
        });

        it('should FAIL if CloudTrail logging bucket has access logging enabled but bucket does not exist', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            };

            const cache = createCache(
                [
                    {
                        "Name": "delete-me-ms",
                        "S3BucketName": "delete-me-ueoeuaou-ms",
                        "IncludeGlobalServiceEvents": true,
                        "IsMultiRegionTrail": true,
                        "HomeRegion": "us-east-1",
                        "TrailARN": "arn:aws:cloudtrail:us-east-1:000000000000:trail/delete-me-ms",
                        "LogFileValidationEnabled": true,
                        "HasCustomEventSelectors": true,
                        "HasInsightSelectors": false,
                        "IsOrganizationTrail": false
                    },
                ],
                {
                    data: {},
                    err: {
                            "message": "The specified bucket does not exist",
                            "code": "NoSuchBucket",
                            "region": null,
                            "time": "2020-08-13T17:17:02.086Z",
                            "requestId": "0000000000000000",
                            "extendedRequestId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "statusCode": 404,
                            "retryable": false,
                            "retryDelay": 52.88593440570173
                    },
                },
                [
                    {
                        "Name": "delete-me-ueoeuaou-ms",
                        "CreationDate": "2020-06-30T14:29:53.000Z"
                    },
                ],
                'delete-me-ueoeuaou-ms'
            );

            eks.run(cache, {}, callback);
        });

        it('should PASS if CloudTrail logging bucket has access logging enabled and bucket is another account, with ignore_bucket_not_in_account enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            };

            const cache = createCache(
                [
                    {
                        "Name": "delete-me-ms",
                        "S3BucketName": "delete-me-ueoeuaou-ms",
                        "IncludeGlobalServiceEvents": true,
                        "IsMultiRegionTrail": true,
                        "HomeRegion": "us-east-1",
                        "TrailARN": "arn:aws:cloudtrail:us-east-1:000000000000:trail/delete-me-ms",
                        "LogFileValidationEnabled": true,
                        "HasCustomEventSelectors": true,
                        "HasInsightSelectors": false,
                        "IsOrganizationTrail": false
                    },
                ],
                {
                    data: {
                        "LoggingEnabled": {
                            "TargetPrefix": "foo",
                            "TargetBucket": "delete-me-ueoeuaou-ms"
                        },
                    },
                },
                [
                    {
                        "Name": "not-delete-me-ueoeuaou-ms",
                        "CreationDate": "2020-06-30T14:29:53.000Z"
                    },
                ],
                'delete-me-ueoeuaou-ms'
            );

            eks.run(cache, {ignore_bucket_not_in_account: true}, callback);
        });
    })
});