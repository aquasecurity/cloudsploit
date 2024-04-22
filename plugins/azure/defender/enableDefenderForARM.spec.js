var expect = require('chai').expect;
var enableDefenderForResourceManager = require('./enableDefenderForARM');

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
    };
};

describe('enableDefenderForResourceManager', function() {
    describe('run', function() {
        it('should give unknown result if unable to query pricing information', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Pricing');
                expect(results[0].region).to.equal('global');
                done();
            };

            const cache = createCache(['error'], null);

            enableDefenderForResourceManager.run(cache, {}, callback);
        });

        it('should give passing result if no pricings found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Pricing information found');
                expect(results[0].region).to.equal('global');
                done();
            };

            const cache = createCache(null, []);

            enableDefenderForResourceManager.run(cache, {}, callback);
        });

        it('should give failing result if Azure Defender for Resource Manager is not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Azure Defender is not enabled for Resource Manager');
                expect(results[0].region).to.equal('global');
                done();
            };

            const cache = createCache(null, [
                {
                    "id": "/subscriptions/12345/providers/Microsoft.Security/pricings/default",
                    "name": "KubernetesService",
                    "type": "Microsoft.Security/pricings",
                    "pricingTier": "free",
                    "location": "global"
                }
            ]);

            enableDefenderForResourceManager.run(cache, {}, callback);
        });

        it('should give passing result if Azure Defender for Resource Manager is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Azure Defender is enabled for Resource Manager');
                expect(results[0].region).to.equal('global');
                done();
            };

            const cache = createCache(null, [
                {
                    "id": "/subscriptions/12345/providers/Microsoft.Security/pricings/default",
                    "name": "arm",
                    "type": "Microsoft.Security/pricings",
                    "pricingTier": "Standard",
                    "location": "global"
                }
            ]);

            enableDefenderForResourceManager.run(cache, {}, callback);
        });
    });
});
