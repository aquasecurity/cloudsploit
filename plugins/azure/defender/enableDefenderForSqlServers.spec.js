const assert = require('assert');
const expect = require('chai').expect;
const plugin = require('./enableDefenderForSqlServers');

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

describe('enableDefenderForSqlServers', function() {
    describe('run', function() {
        it('should give passing result if no pricings found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Pricing information found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(null, []);
            plugin.run(cache, {}, callback);
        });

        it('should give failing result if Azure Defender for SQL Servers is not enabled', function(done) {
            const callback = (err, results) => {
                console.log(results[0])
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Azure Defender is not enabled for SQL Servers');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/providers/Microsoft.Security/pricings/SqlServers",
                        "name": "SqlServers",
                        "type": "Microsoft.Security/pricings",
                        "pricingTier": "Free"
                        
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Azure Defender for SQL Servers is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Azure Defender is enabled for SQL Servers');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/providers/Microsoft.Security/pricings/SqlServers",
                        "name": "SqlServers",
                        "type": "Microsoft.Security/pricings",
                        "pricingTier": "Standard"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query pricing information', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Pricing information');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(new Error('API error'));
            plugin.run(cache, {}, callback);
        });
    });
}); 