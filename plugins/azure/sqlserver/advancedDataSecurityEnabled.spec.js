var expect = require('chai').expect;
var advancedDataSecurityEnabled = require('./advancedDataSecurityEnabled');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
    }
];

const serverSecurityAlertPolicies = [
    {
        "id": '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/securityAlertPolicies/Default', 
        "name": 'Default',
        "type": 'Microsoft.Sql/servers/securityAlertPolicies',
        "state": 'Enabled'
    },
    {
        "id": '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/securityAlertPolicies/Default', 
        "name": 'Default',
        "type": 'Microsoft.Sql/servers/securityAlertPolicies',
        "state": 'Disabled'
    }
];

const createCache = (servers, policies, serversErr, policiesErr) => {
    const serverId = (servers && servers.length) ? servers[0].id : null;
    return {
        servers: {
            listSql: {
                'eastus': {
                    err: serversErr,
                    data: servers
                }
            }
        },
        serverSecurityAlertPolicies: {
            listByServer: {
                'eastus': {
                    [serverId]: {
                        err: policiesErr,
                        data: policies
                    }
                }
            }
        }
    }
};

describe('advancedDataSecurityEnabled', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            advancedDataSecurityEnabled.run(cache, {}, callback);
        });

        it('should give failing result if no Database Threat Detection policies found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No Database Threat Detection policies found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                []
            );

            advancedDataSecurityEnabled.run(cache, {}, callback);
        });

        it('should give failing result if Advanced Data Security for the SQL server is disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Advanced Data Security for the SQL server is disabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [serverSecurityAlertPolicies[1]]
            );

            advancedDataSecurityEnabled.run(cache, {}, callback);
        });

        it('should give passing result if Advanced Data Security for the SQL server is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Advanced Data Security for the SQL server is enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [serverSecurityAlertPolicies[0]]
            );

            advancedDataSecurityEnabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [],
                { message: 'unable to query servers'}
            );

            advancedDataSecurityEnabled.run(cache, {}, callback);
        });

        it('should give unknown result if Unable to query for Database Threat Detection Policies', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Database Threat Detection Policies');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [],
                null,
                { message: 'Unable to query for Database Threat Detection Policies'}
            );

            advancedDataSecurityEnabled.run(cache, {}, callback);
        });
    })
})