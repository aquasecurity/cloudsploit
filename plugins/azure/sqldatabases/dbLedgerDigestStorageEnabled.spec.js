var expect = require('chai').expect;
var enableAutomaticLedgerDigestStorage = require('./dbLedgerDigestStorageEnabled');

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

const ledgerDigestUploads = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/ledgerDigestUploads/1",
        "state": "Enabled",
    },
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/ledgerDigestUploads/2",
        "state": "Disabled",
    },
];

const createCache = (servers, databases, ledgerDigestUploads, serversErr, databasesErr, ledgerDigestUploadsErr) => {
    const serverId = (servers && servers.length) ? servers[0].id : null;
    const databaseId = (databases && databases.length) ? databases[0].id : null;
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
        ledgerDigestUploads: {
            list: {
                'eastus': {
                    [databaseId]: {
                        err: ledgerDigestUploadsErr,
                        data: ledgerDigestUploads
                    }
                }
            }
        }
    };
};

describe('enableAutomaticLedgerDigestStorage', function() {
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
                [],
                databases,
                ledgerDigestUploads
            );

            enableAutomaticLedgerDigestStorage.run(cache, {}, callback);
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
                [],
                ledgerDigestUploads
            );

            enableAutomaticLedgerDigestStorage.run(cache, {}, callback);
        });

        it('should give passing result if Automatic Ledger digest storage is enabled for the database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Ledger automatic digest storage is enabled for SQL database');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                [ledgerDigestUploads[0]]
            );

            enableAutomaticLedgerDigestStorage.run(cache, {}, callback);
        });

        it('should give failing result if Automatic Ledger digest storage is disabled for the database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Ledger automatic digest storage is not enabled for SQL database');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                [ledgerDigestUploads[1]]
            );

            enableAutomaticLedgerDigestStorage.run(cache, {}, callback);
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
                databases,
                ledgerDigestUploads,
                { message: 'unable to query servers' }
            );

            enableAutomaticLedgerDigestStorage.run(cache, {}, callback);
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
                ledgerDigestUploads,
                null,
                { message: 'unable to query databases' }
            );

            enableAutomaticLedgerDigestStorage.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for Azure ledger', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Ledger Digest Uploads for SQL database:');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                null,
                null,
                null,
                { message: 'unable to query ledger' }
            );

            enableAutomaticLedgerDigestStorage.run(cache, {}, callback);
        });
    });
});
