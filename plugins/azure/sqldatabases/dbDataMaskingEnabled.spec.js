var expect = require('chai').expect;
var setDynamicDataMasking = require('./dbDataMaskingEnabled');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
    }
];

const databases = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database",
    }
];

const dataMaskingPolicies = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/datamaskingpolicies/default",
        "name": "default",
        "type": "Microsoft.Sql/servers/databases/datamaskingpolicies",
        "dataMaskingState": "Enabled",
    },
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/datamaskingpolicies/default",
        "name": "default",
        "type": "Microsoft.Sql/servers/databases/datamaskingpolicies",
        "dataMaskingState": "Disabled",
    }
];

const createCache = (servers, databases, dataMaskingPolicies, serversErr, databasesErr) => {
    const serverId = (servers && servers.length) ? servers[0].id : null;
    const dbId = (databases && databases.length) ? databases[0].id : null;
    return {
        servers: {
            listSql: {
                'eastus': {
                    err: serversErr,
                    data: servers
                }
            }
        },
        databases: {
            listByServer: {
                'eastus': {
                    [serverId]: {
                        err: databasesErr,
                        data: databases
                    }
                }
            }
        },
        dataMaskingPolicies: {
            get: {
                'eastus': {
                    [dbId]: {
                        data: dataMaskingPolicies
                    }
                }
            }
        }
    };
};

describe('setDynamicDataMasking', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                []
            );

            setDynamicDataMasking.run(cache, {}, callback);
        });

        it('should give passing result if no databases found for SQL server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No databases found for SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                []
            );

            setDynamicDataMasking.run(cache, {}, callback);
        });

        it('should give passing result if Dynamic data masking is enabled for SQL database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Dynamic data masking is enabled for SQL database');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                dataMaskingPolicies[0]
            );

            setDynamicDataMasking.run(cache, {}, callback);
        });

        it('should give failing result if Dynamic data masking is not enabled for SQL database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Dynamic data masking is not enabled for SQL database');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                dataMaskingPolicies[1]
            );

            setDynamicDataMasking.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('unable to query servers');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [],
                [],
                [],
                { message: 'unable to query servers' }
            );

            setDynamicDataMasking.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL server databases', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('unable to query databases');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                [],
                null,
                { message: 'unable to query databases' }
            );

            setDynamicDataMasking.run(cache, {}, callback);
        });
    });
});
