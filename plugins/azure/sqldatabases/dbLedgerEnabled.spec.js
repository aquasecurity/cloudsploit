var expect = require('chai').expect;
var enableAzureLedger = require('./dbLedgerEnabled');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
    }
];

const databases = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database",
        "name": "test-database",
        "isLedgerOn": true,
    },
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database",
        "name": "test-database",
        "isLedgerOn": false,
    }
];

const createCache = (servers, databases, serversErr, databasesErr) => {
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
        databases: {
            listByServer: {
                'eastus': {
                    [serverId]: {
                        err: databasesErr,
                        data: databases
                    }
                }
            }
        }
    };
};

describe('enableAzureLedger', function() {
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

            enableAzureLedger.run(cache, {}, callback);
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

            enableAzureLedger.run(cache, {}, callback);
        });

        it('should give passing result if Ledger is enabled for the database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Ledger is enabled for SQL database');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                [databases[0]]
            );

            enableAzureLedger.run(cache, {}, callback);
        });

        it('should give failing result if Ledger is not enabled for the database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Ledger is not enabled for SQL database');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                [databases[1]]
            );

            enableAzureLedger.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [],
                [],
                { message: 'unable to query servers' }
            );

            enableAzureLedger.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL server databases', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL server databases');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                [],
                null,
                { message: 'unable to query databases' }
            );

            enableAzureLedger.run(cache, {}, callback);
        });
    });
});
