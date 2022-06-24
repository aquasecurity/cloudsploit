var expect = require('chai').expect;
var plugin = require('./instanceNodeCount');

const createCache = (err, data) => {
    return {
        instances: {
            spanner: {
                list: {
                    'global': {
                        err: err,
                        data: data
                    }
                }
            }
        }
    }
};

describe('instanceNodeCount', function () {
    describe('run', function () {
        it('should give unknown result if error while querying Spanner instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Spanner instances');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                ['error'],
                null,
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no Spanner instances found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Spanner instances found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if instance has less nodes than allowed limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Spanner instance has 1 node of 20 limit');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        "name": "projects/test-aqua/instances/test-ins",
                        "config": "projects/test-aqua/instanceConfigs/regional-us-east1",
                        "displayName": "test-ins",
                        "nodeCount": 1,
                        "state": "READY",
                        "processingUnits": 1000
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if instance has more nodes that allowed limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Spanner instance has 21 node of 20 limit');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        "name": "projects/test-aqua/instances/test-ins",
                        "config": "projects/test-aqua/instanceConfigs/regional-asia1",
                        "displayName": "test-ins",
                        "nodeCount": 21,
                        "state": "READY",
                        "processingUnits": 1000
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
    })
});