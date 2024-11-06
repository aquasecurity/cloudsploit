const expect = require('chai').expect;
const enableTransparentDataEncryption = require('./dbTDEEnabled');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
    }
];

const managedInstances = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/managedInstances/test-instance",
        "name": "test-instance"
    }
];

const databases = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database",
        "name": "test-database",
    }
];

const managedDatabases = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/managedInstances/test-instance/databases/test-database",
        "name": "test-database"
    }
];

const transparentDataEncryptionEnabled = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/transparentDataEncryption/1",
        "state": "Enabled"
    }
];

const createCache = (servers, databases, transparentDataEncryption, managedInstances, managedDatabases, serversErr, databasesErr, transparentDataEncryptionErr, managedInstancesErr, managedDatabasesErr) => {
    const serverId = (servers && servers.length) ? servers[0].id : null;
    const databaseId = (databases && databases.length) ? databases[0].id : null;
    const managedInstanceId = (managedInstances && managedInstances.length) ? managedInstances[0].id : null;
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
        },
        managedInstances: {
            list: {
                'eastus': {
                    err: managedInstancesErr,
                    data: managedInstances
                }
            }
        },
        managedDatabases: {
            listByInstance: {
                'eastus': {
                    [managedInstanceId]: {
                        err: managedDatabasesErr,
                        data: managedDatabases
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
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [], databases, transparentDataEncryptionEnabled,
                [], []
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give passing result if no databases found for SQL server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No databases found for SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers, [], transparentDataEncryptionEnabled,
                [], []
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give passing result if SQL Database transparent data encryption is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Database: Transparent data encryption is enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers, databases, transparentDataEncryptionEnabled,
                [], []
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give failing result if SQL Database transparent data encryption is disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL Database: Transparent data encryption is not enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers, databases,
                [
                    {
                        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/transparentDataEncryption/1",
                        "state": "Disabled"
                    }
                ],
                [], []
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give passing result if no managed instances found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('No managed instances found');
                expect(results[1].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [], [], [],
                [], []
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give passing result if no databases found for managed instance', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('No databases found for managed instance');
                expect(results[1].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [], [], [],
                managedInstances, []
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give passing result for managed instance database (TDE always enabled)', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('Managed Instance Database: Transparent data encryption is enabled');
                expect(results[1].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [], [], [],
                managedInstances, managedDatabases
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [], [], [],
                [], [],
                { message: 'unable to query servers' }
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL server databases', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL server databases');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers, [], [],
                [], [],
                null, { message: 'unable to query databases' }
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for managed instances', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(3);
                expect(results[1].message).to.include('Unable to query for managed instances');
                expect(results[1].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [], [], [],
                [], [],
                null, null, null,
                { message: 'unable to query managed instances' }
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for managed instance databases', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(3);
                expect(results[1].message).to.include('Unable to query for managed instance databases');
                expect(results[1].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [], [], [],
                managedInstances, [],
                null, null, null, null,
                { message: 'unable to query managed databases' }
            );

            enableTransparentDataEncryption.run(cache, {}, callback);
        });
    });
});
