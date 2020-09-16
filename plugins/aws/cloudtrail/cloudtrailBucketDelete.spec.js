const assert = require('assert');
const expect = require('chai').expect;
const eks = require('./cloudtrailBucketDelete');
const createCache = (descTrailsData, getBuckVerData, listBuckData, buckName) => {
    let to_return = {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    data: descTrailsData
                }
            },
        },
        s3: {
            getBucketVersioning: {
                'us-east-1': {}
            },
            listBuckets: {
                'us-east-1': {
                    data: listBuckData
                }
            },
        }
    };
    to_return.s3.getBucketVersioning['us-east-1'][buckName] = getBuckVerData;
    return to_return
};

describe('cloudtrailBucketDelete', function () {
    describe('run', function () {
        it('should PASS if CloudTrail logging bucket has MFADelete enabled', function (done) {
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
                      "Status": "Enabled",
                      "MFADelete": "Enabled"
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

        it('should WARN if CloudTrail logging bucket has MFADelete disabled', function (done) {
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
                  data: {
                      "Status": "Enabled",
                      "MFADelete": "Disabled"
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

        it('should FAIL if CloudTrail logging bucket does not exist', function (done) {
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

        it('should PASS if CloudTrail logging bucket is in another account, with ignore_bucket_not_in_account enabled', function (done) {
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
                    data: {},
                    err: {
                            "message": "Access Denied",
                            "code": "AccessDenied",
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
                        "Name": "not-delete-me-ueoeuaou-ms",
                        "CreationDate": "2020-06-30T14:29:53.000Z"
                    },
                ],
                'delete-me-ueoeuaou-ms'
            );

            eks.run(cache, {ignore_bucket_not_in_account: true}, callback);
        });

        it('should UNKNOWN if CloudTrail logging bucket is in another account, with ignore_bucket_not_in_account disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
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
                            "message": "Access Denied",
                            "code": "AccessDenied",
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
                        "Name": "not-delete-me-ueoeuaou-ms",
                        "CreationDate": "2020-06-30T14:29:53.000Z"
                    },
                ],
                'delete-me-ueoeuaou-ms'
            );

            eks.run(cache, {ignore_bucket_not_in_account: false}, callback);
        });
    })
});