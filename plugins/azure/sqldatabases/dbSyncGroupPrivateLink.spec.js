var expect = require('chai').expect;
var sqlDatabaseSyncGroups = require('./dbSyncGroupPrivateLink');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
    }
];

const databases = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database"
    }
];

const syncGroups = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/syncGroups/1",
        "usePrivateLinkConnection": true
    }
];

const createCache = (servers, databases, syncGroups, serversErr, databasesErr, syncGroupsErr) => {
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
        syncGroups: {
            list: {
                'eastus': {
                    [databaseId]: {
                        err: syncGroupsErr,
                        data: syncGroups
                    }
                }
            }
        }
    };
};

describe('sqlDatabaseSyncGroups', function() {
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
                syncGroups
            );

            sqlDatabaseSyncGroups.run(cache, {}, callback);
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
                syncGroups
            );

            sqlDatabaseSyncGroups.run(cache, {}, callback);
        });

        it('should give passing result if SQL Database sync group uses private link', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('All SQL Database sync groups are configured to use private link');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                syncGroups
            );

            sqlDatabaseSyncGroups.run(cache, {}, callback);
        });

        it('should give failing result if SQL Database sync group does not use private link', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Following SQL Database sync groups are not configured to use private link:');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                [
                    {
                        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/syncGroups/1",
                        "usePrivateLinkConnection": false
                    }
                ]
            );

            sqlDatabaseSyncGroups.run(cache, {}, callback);
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
                syncGroups,
                { message: 'unable to query servers' }
            );

            sqlDatabaseSyncGroups.run(cache, {}, callback);
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
                syncGroups,
                null,
                { message: 'unable to query databases' }
            );

            sqlDatabaseSyncGroups.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL Database sync groups', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL Database sync groups');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                [],
                null,
                null,
                { message: 'unable to query sync groups' }
            );

            sqlDatabaseSyncGroups.run(cache, {}, callback);
        });
    });
});
