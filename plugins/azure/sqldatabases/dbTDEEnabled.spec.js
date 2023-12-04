var expect = require('chai').expect;
var enableTransparentDataEncryption = require('./dbTDEEnabled');

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

const transparentDataEncryptionEnabled = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/transparentDataEncryption/1",
        "state": "Enabled"
    }
];

const createCache = (servers, databases, transparentDataEncryption, serversErr, databasesErr, transparentDataEncryptionErr) => {
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
        transparentDataEncryption: {
            list: {
                'eastus': {
                    [databaseId]: {
                        err: transparentDataEncryptionErr,
                        data: transparentDataEncryption
                    }
                }
            }
        }
    };
};

describe('enableTransparentDataEncryption', function() {
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
                transparentDataEncryptionEnabled
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
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
                transparentDataEncryptionEnabled
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give passing result if SQL Database transparent data encryption is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Transparent data encryption is enabled for SQL Database');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                transparentDataEncryptionEnabled
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give failing result if SQL Database transparent data encryption is disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Transparent data encryption is not enabled for SQL Database');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                [
                    {
                        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/transparentDataEncryption/1",
                        "state": "Disabled"
                    }
                ]
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
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
                transparentDataEncryptionEnabled,
                { message: 'unable to query servers' }
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
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
                transparentDataEncryptionEnabled,
                null,
                { message: 'unable to query databases' }
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL Database transparent data encryption', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query transparent data encryption for SQL Database');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                [],
                null,
                null,
                { message: 'unable to query transparent data encryption' }
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });
    });
});
