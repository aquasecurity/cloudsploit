var expect = require('chai').expect;
var plugin = require('./cloudguardEnabled');

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

        cloudguardConfiguration: {
            get: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('cloudguardEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a configuration error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for cloud guard configuration')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        
        it('should give passing result cloud guard is enabled in the root compartment of the tenancy', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('is enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                {
                    reportingRegion: 'us-ashburn-1',
                    status: 'ENABLED',
                    selfManageResources: false
                }
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if cloud guard is not enabled in the root compartment of the tenancy', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('is not enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                {
                    reportingRegion: 'us-ashburn-1',
                    status: 'DISABLED',
                    selfManageResources: false
                }
            );

            plugin.run(cache, {}, callback);
        })
    })
})