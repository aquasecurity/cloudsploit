var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./bucketAllUsersPolicy');

const createCache = (err, data, bucketErr, bucketData) => {
    return {
        buckets: {
            list: {
                'global': {
                    err: bucketErr,
                    data: bucketData
                }
            },
            getIamPolicy: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('bucketAllUsersPolicy', function () {
    describe('run', function () {
        it('should give unknown result if a bucket error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query storage buckets');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no buckets are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage buckets found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                null,
                null,
                [
                        {
                            "kind": "storage#buckets"
                        }
                    ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no buckets have anonymous or public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bucket does not have anonymous or public access');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "storage#policy",
                        "resourceId": "projects/_/buckets/us.artifacts.rosy-booth-253119.appspot.com",
                        "bindings": [
                            {
                                "role": "roles/storage.legacyBucketOwner",
                                "members": [
                                    "projectEditor:rosy-booth-253119",
                                    "projectOwner:rosy-booth-253119"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketReader",
                                "members": [
                                    "projectViewer:rosy-booth-253119"
                                ]
                            }
                        ],
                        "etag": "CAE=",
                        "version": 1
                    },
                    {
                        "kind": "storage#policy",
                        "resourceId": "projects/_/buckets/staging.rosy-booth-253119.appspot.com",
                        "bindings": [
                            {
                                "role": "roles/storage.legacyBucketOwner",
                                "members": [
                                    "projectEditor:rosy-booth-253119",
                                    "projectOwner:rosy-booth-253119"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketReader",
                                "members": [
                                    "projectViewer:rosy-booth-253119"
                                ]
                            }
                        ],
                        "etag": "CAE=",
                        "version": 1
                    },
                    {
                        "kind": "storage#policy",
                        "resourceId": "projects/_/buckets/rosy-booth-253119.appspot.com",
                        "version": 1,
                        "bindings": [
                            {
                                "role": "roles/iam.securityReviewer",
                                "members": [
                                    "projectEditor:rosy-booth-253119",
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketOwner",
                                "members": [
                                    "projectEditor:rosy-booth-253119",
                                    "projectOwner:rosy-booth-253119"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketReader",
                                "members": [
                                    "projectViewer:rosy-booth-253119"
                                ]
                            }
                        ],
                        "etag": "CAs="
                    }
                ],
                null,
                [
                    {
                        "kind": "storage#bucket",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/testio",
                        "id": "testio",
                        "name": "testio",
                        "projectNumber": "664367550207",
                        "metageneration": "1",
                        "location": "US",
                        "storageClass": "STANDARD",
                        "etag": "CAE=",
                        "defaultEventBasedHold": false,
                        "timeCreated": "2021-04-06T16:06:14.799Z",
                        "updated": "2021-04-06T16:06:14.799Z",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": true,
                                "lockedTime": "2021-07-05T16:06:14.799Z"
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": true,
                                "lockedTime": "2021-07-05T16:06:14.799Z"
                            }
                        },
                        "locationType": "multi-region",
                        "satisfiesPZS": false
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if bucket has anonymous or public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket has anonymous or public access');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "storage#policy",
                        "resourceId": "projects/_/buckets/us.artifacts.rosy-booth-253119.appspot.com",
                        "bindings": [
                            {
                                "role": "roles/storage.legacyBucketOwner",
                                "members": [
                                    "projectEditor:rosy-booth-253119",
                                    "projectOwner:rosy-booth-253119"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketReader",
                                "members": [
                                    "projectViewer:rosy-booth-253119"
                                ]
                            }
                        ],
                        "etag": "CAE=",
                        "version": 1
                    },
                    {
                        "kind": "storage#policy",
                        "resourceId": "projects/_/buckets/staging.rosy-booth-253119.appspot.com",
                        "bindings": [
                            {
                                "role": "roles/storage.legacyBucketOwner",
                                "members": [
                                    "projectEditor:rosy-booth-253119",
                                    "projectOwner:rosy-booth-253119"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketReader",
                                "members": [
                                    "projectViewer:rosy-booth-253119"
                                ]
                            }
                        ],
                        "etag": "CAE=",
                        "version": 1
                    },
                    {
                        "kind": "storage#policy",
                        "resourceId": "projects/_/buckets/rosy-booth-253119.appspot.com",
                        "version": 1,
                        "bindings": [
                            {
                                "role": "roles/iam.securityReviewer",
                                "members": [
                                    "allUsers"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketOwner",
                                "members": [
                                    "projectEditor:rosy-booth-253119",
                                    "projectOwner:rosy-booth-253119"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketReader",
                                "members": [
                                    "allUsers",
                                    "projectViewer:rosy-booth-253119"
                                ]
                            }
                        ],
                        "etag": "CAs="
                    }
                ],
                null,
                [
                    {
                        "kind": "storage#bucket",
                        "selfLink": "https://www.googleapis.com/storage/v1/b/testio",
                        "id": "testio",
                        "name": "testio",
                        "projectNumber": "664367550207",
                        "metageneration": "1",
                        "location": "US",
                        "storageClass": "STANDARD",
                        "etag": "CAE=",
                        "defaultEventBasedHold": false,
                        "timeCreated": "2021-04-06T16:06:14.799Z",
                        "updated": "2021-04-06T16:06:14.799Z",
                        "iamConfiguration": {
                            "bucketPolicyOnly": {
                                "enabled": true,
                                "lockedTime": "2021-07-05T16:06:14.799Z"
                            },
                            "uniformBucketLevelAccess": {
                                "enabled": true,
                                "lockedTime": "2021-07-05T16:06:14.799Z"
                            }
                        },
                        "locationType": "multi-region",
                        "satisfiesPZS": false
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
});