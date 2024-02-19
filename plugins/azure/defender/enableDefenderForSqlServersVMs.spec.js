var expect = require('chai').expect;
var enableDefenderForSQLServers = require('./enableDefenderForSqlServersVMs');

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

describe('enableDefenderForSQLServers', function() {
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

            enableDefenderForSQLServers.run(cache, {}, callback);
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

            enableDefenderForSQLServers.run(cache, {}, callback);
        });

        it('should give failing result if Azure Defender for SQL Servers on machines is not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Azure Defender is not enabled for SQL Servers on machines');
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

            enableDefenderForSQLServers.run(cache, {}, callback);
        });

        it('should give passing result if Azure Defender for SQL Servers on machines is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Azure Defender is enabled for SQL Servers on machines');
                expect(results[0].region).to.equal('global');
                done();
            };

            const cache = createCache(null, [
                {
                    "id": "/subscriptions/12345/providers/Microsoft.Security/pricings/default",
                    "name": "SQLServerVirtualMachines",
                    "type": "Microsoft.Security/pricings",
                    "pricingTier": "Standard",
                    "location": "global"
                }
            ]);

            enableDefenderForSQLServers.run(cache, {}, callback);
        });
    });
});
