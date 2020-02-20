var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./logRetentionPeriod');

const createCache = (err, data) => {
    return {
        regionSubscription: {
            "list": {
                "us-ashburn-1": {
                    "data": [
                        {
                            "regionKey": "IAD",
                            "regionName": "us-ashburn-1",
                            "status": "READY",
                            "isHomeRegion": true
                        },
                        {
                            "regionKey": "LHR",
                            "regionName": "uk-london-1",
                            "status": "READY",
                            "isHomeRegion": false
                        },
                        {
                            "regionKey": "PHX",
                            "regionName": "us-phoenix-1",
                            "status": "READY",
                            "isHomeRegion": false
                        }
                    ]
                }
            }
        },

        configuration: {
            get: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('logRetentionPeriod', function () {
    describe('run', function () {
        it('should give unknown result if a configuration error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for audit configurations')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no configuration records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No audit configurations found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if the log retention period is as long as the configured period', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Audit configuration period is')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                {
                    retentionPeriodDays: 365
                }
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if the log retention period is not as long as the configured period', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Audit configuration period is')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                {
                    retentionPeriodDays: 90
                }
            );

            plugin.run(cache, {}, callback);
        })
    })
})