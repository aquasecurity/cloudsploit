var expect = require('chai').expect;
var plugin = require('./bucketLogging');

const createCache = (err, data) => {
    return {
        buckets: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('bucketLogging', function () {
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
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no storage buckets found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage buckets found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if bucket logging is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bucket Logging Enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        kind: "storage#bucket",
                        selfLink: "https://www.googleapis.com/storage/v1/b/test_bucket_spec1",
                        id: "test_bucket_spec1",
                        name: "test_bucket_spec1",
                        projectNumber: "dummy1",
                        metageneration: "3",
                        location: "US",
                        storageClass: "STANDARD",
                        etag: "CAM=",
                        defaultEventBasedHold: false,
                        timeCreated: "2021-04-07T17:55:53.104Z",
                        updated: "2021-04-07T19:03:16.173Z",
                        logging: {
                          logBucket: "akhtar-bucket-1",
                          logObjectPrefix: "test_bucket_spec1",
                        },
                        iamConfiguration: {
                          bucketPolicyOnly: {
                            enabled: true,
                            lockedTime: "2021-07-06T17:55:53.104Z",
                          },
                          uniformBucketLevelAccess: {
                            enabled: true,
                            lockedTime: "2021-07-06T17:55:53.104Z",
                          },
                        },
                        locationType: "multi-region",
                        satisfiesPZS: false,
                    },
                    
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if bucket logging is not enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket Logging not Enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        kind: "storage#bucket",
                        selfLink: "https://www.googleapis.com/storage/v1/b/test_bucket_spec1",
                        id: "test_bucket_spec1",
                        name: "test_bucket_spec1",
                        projectNumber: "dummy1",
                        metageneration: "3",
                        location: "US",
                        storageClass: "STANDARD",
                        etag: "CAM=",
                        defaultEventBasedHold: false,
                        timeCreated: "2021-04-07T17:55:53.104Z",
                        updated: "2021-04-07T19:03:16.173Z",
                        iamConfiguration: {
                          bucketPolicyOnly: {
                            enabled: true,
                            lockedTime: "2021-07-06T17:55:53.104Z",
                          },
                          uniformBucketLevelAccess: {
                            enabled: true,
                            lockedTime: "2021-07-06T17:55:53.104Z",
                          },
                        },
                        locationType: "multi-region",
                        satisfiesPZS: false,
                    },
                ],
            );
            plugin.run(cache, {}, callback);
        });
    })
});
