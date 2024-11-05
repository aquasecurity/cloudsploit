const assert = require('assert');
const expect = require('chai').expect;
const plugin = require('./enableDefenderForSqlServers');

describe('enableDefenderForSqlServers', function() {
    describe('run', function() {
        it('should give passing result if Defender is enabled at subscription level', function(done) {
            const cache = createCache([{
                id: '/subscriptions/123/providers/Microsoft.Security/pricings/SqlServers',
                name: 'SqlServers',
                pricingTier: 'Standard'
            }]);
            const settings = {
                check_level: 'subscription'
            };

            plugin.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Azure Defender is enabled for SQL Servers at subscription level');
                done();
            });
        }); 

        it('should give failing result if Defender is not enabled at subscription level', function(done) {
            const cache = createCache([{
                id: '/subscriptions/123/providers/Microsoft.Security/pricings/SqlServers',
                name: 'SqlServers',
                pricingTier: 'Free'
            }]);
            const settings = {
                check_level: 'subscription'
            };

            plugin.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Azure Defender is not enabled for SQL Servers at subscription level');
                done();
            });
        });

        it('should give passing result if Defender is enabled at resource level', function(done) {
            const cache = createCache(
                [{
                    id: '/subscriptions/123/providers/Microsoft.Security/pricings/SqlServers',
                    name: 'SqlServers',
                    pricingTier: 'Free'
                }],
                [{
                    id: '/subscriptions/123/servers/test-server'
                }],
                [{
                    id: '/subscriptions/123/servers/test-server/security',
                    state: 'Enabled'
                }]
            );
            const settings = {
                check_level: 'resource'
            };

            plugin.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Azure Defender is enabled for SQL server');
                done();
            });
        });

        it('should give failing result if Defender is not enabled at resource level', function(done) {
            const cache = createCache(
                [{
                    id: '/subscriptions/123/providers/Microsoft.Security/pricings/SqlServers',
                    name: 'SqlServers',
                    pricingTier: 'Free'
                }],
                [{
                    id: '/subscriptions/123/servers/test-server'
                }],
                [{
                    id: '/subscriptions/123/servers/test-server/security',
                    state: 'Disabled'
                }]
            );
            const settings = {
                check_level: 'resource'
            };

            plugin.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Azure Defender is not enabled for SQL server');
                done();
            });
        });

        // Add other necessary test cases for error conditions
    });
});

function createCache(pricingData, serversData, securityData) {
    return {
        pricings: {
            list: {
                global: {
                    data: pricingData
                }
            }
        },
        servers: {
            listSql: {
                'eastus': {
                    data: serversData
                }
            }
        },
        serverSecurityAlertPolicies: {
            listByServer: {
                'eastus': {
                    '/subscriptions/123/servers/test-server': {
                        data: securityData
                    }
                }
            }
        }
    };
} 