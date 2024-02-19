const assert = require('assert');
const expect = require('chai').expect;
const connectionPolicyPlugin = require('./serverConnectionPolicy'); // Update the path accordingly

const createCache = (servers, connectionPolicies, serversErr, connectionPoliciesErr) => {
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
        connectionPolicies: {
            listByServer: {
                'eastus': {
                    [serverId]: {
                        err: connectionPoliciesErr,
                        data: connectionPolicies
                    }
                }
            }
        }
    };
};

describe('sqlServerConnectionPolicy', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([]);

            connectionPolicyPlugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers:');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(null);

            connectionPolicyPlugin.run(cache, {}, callback);
        });

        it('should give passing result if connection policy is set to "Redirect"', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Connection policy is set to "Redirect" for SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [
                    {
                        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server',
                        'name': 'test-server',
                        'location': 'eastus'
                    }
                ],
                [
                    {
                        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/connectionPolicies/Default',
                        'name': 'Default',
                        'type': 'Microsoft.Sql/servers/connectionPolicies',
                        'connectionType': 'Redirect'
                    }
                ]
            );

            connectionPolicyPlugin.run(cache, {}, callback);
        });

        it('should give failing result if connection policy is not set to "Redirect"', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Connection policy is not set to "Redirect" for SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [
                    {
                        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server',
                        'name': 'test-server',
                        'location': 'eastus'
                    }
                ],
                [
                    {
                        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/connectionPolicies/Default',
                        'name': 'Default',
                        'type': 'Microsoft.Sql/servers/connectionPolicies',
                        'connectionType': 'NotRedirect'
                    }
                ]
            );

            connectionPolicyPlugin.run(cache, {}, callback);
        });

        it('should give passing result if no Connection policies found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Connection policies found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [
                    {
                        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server',
                        'name': 'test-server',
                        'location': 'eastus'
                    }
                ],
                []
            );

            connectionPolicyPlugin.run(cache, {}, callback);
        });

    });
});
