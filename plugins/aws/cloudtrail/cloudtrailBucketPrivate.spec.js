const assert = require('assert');
const expect = require('chai').expect;
const eks = require('./cloudtrailBucketPrivate');
const createCache = (descTrailsData, getBuckAclData, listBuckData, buckName) => { // todo
    let to_return = {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    data: descTrailsData
                }
            },
        },
        s3: {
            getBucketAcl: {
                'us-east-1': {}
            },
            listBuckets: {
                'us-east-1': {
                    data: listBuckData
                }
            },
        }
    };
    to_return.s3.getBucketAcl['us-east-1'][buckName] = getBuckAclData;
    return to_return
};

describe('cloudtrailBucketPrivate', function () {
    describe('run', function () {
        it('should PASS if CloudTrail logging bucket is NOT publicly accessible', function (done) {
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
                      "Owner": {
                          "DisplayName": "bar",
                          "ID": "7009a8971cd538e11f6b6606438875e7c86c5b672f46db45460ddcd087d36c33"
                      },
                      "Grants": [
                          {
                              "Grantee": {
                                  "DisplayName": "foo",
                                  "ID": "7009a8971cd538e11f6b6606438875e7c86c5b672f46db45460ddcd087d36c32"
                              },
                              "Permission": "FULL_CONTROL"
                          }
                      ],
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

        it('should FAIL if CloudTrail logging bucket IS publicly accessible', function (done) {
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
                  data: {
                      "Owner": {
                          "DisplayName": "bar",
                          "ID": "7009a8971cd538e11f6b6606438875e7c86c5b672f46db45460ddcd087d36c33"
                      },
                      "Grants": [
                          {
                              "Grantee": {
                                  "Type": "Group",
                                  "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                              },
                              "Permission": "FULL_CONTROL"
                          }
                      ],
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