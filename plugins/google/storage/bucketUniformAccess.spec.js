var expect = require('chai').expect;
var plugin = require('./bucketUniformAccess');

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

describe('bucketUniformAccess', function () {
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
        it('should give passing result if bucket has uniform bucket level access enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bucket has uniform bucket level access enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        id: "uniform-access",
                        name: "uniform-access",
                        iamConfiguration: {
                          uniformBucketLevelAccess: {
                            enabled: true,
                          },
                        },
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if bucket does not have uniform bucket level access enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket does not have uniform bucket level access enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        id: "uniform-access-2",
                        name: "uniform-access-2",
                        iamConfiguration: {
                          uniformBucketLevelAccess: {
                            enabled: false,
                          },
                        },
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
    })
});