var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./standardPricingEnabled');

const createCache = (err, data) => {
    return {
        pricings: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('standardPricingEnabled', function() {
    describe('run', function() {
        it('should give passing result if no pricings found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No security center pricings found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if disable App Service', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Standard pricing is not enabled for the service');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/providers/Microsoft.Security/pricings/default",
                        "name": "default",
                        "type": "Microsoft.Security/pricings",
                        "pricingTier": "free",
                        "location": "global"
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if enabled App Service', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Standard pricing is enabled for the service');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/providers/Microsoft.Security/pricings/default",
                        "name": "default",
                        "type": "Microsoft.Security/pricings",
                        "pricingTier": "Standard",
                        "location": "global"
                    }
                ]
            );

            auth.run(cache, {}, callback);
        })
    })
})