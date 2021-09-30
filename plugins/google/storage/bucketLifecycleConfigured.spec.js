var expect = require('chai').expect;
var plugin = require('./bucketLifecycleConfigured');

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

describe('bucketLifecycleConfigured', function () {
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
        it('should give passing result if lifecycle management rules are configured', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bucket has lifecycle management configured');
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
                        lifecycle: {
                            rule: [{ action: { type: 'Delete' }, condition: { age: 15 } }]
                        }
                    },

                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if bucket has no lifecycle management configuration', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket does not have lifecycle management configured');
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
                        name: "test_bucket_spec1"
                    },
                ],
            );
            plugin.run(cache, {}, callback);
        });
    })
});
