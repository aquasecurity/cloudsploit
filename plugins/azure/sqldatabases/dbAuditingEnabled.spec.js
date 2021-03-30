var expect = require('chai').expect;
var dbAuditingEnabled = require('./dbAuditingEnabled');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
    }
];

const databases = [
    {
       id: '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/master',
    }
];

const databaseBlobAuditingPolicies = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/master/auditingSettings/Default",
        "name": "Default",
        "type": "Microsoft.Sql/servers/databases/auditingSettings",
        "retentionDays": 9,
        "isAzureMonitorTargetEnabled": true,
        "state": "Enabled",
    },
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/master/auditingSettings/Default",
        "name": "Default",
        "type": "Microsoft.Sql/servers/databases/auditingSettings",
        "retentionDays": 9,
        "isAzureMonitorTargetEnabled": true,
        "state": "Disabled",
    }
];

const createCache = (servers, databases, databaseBlobAuditingPolicies, serversErr, databasesErr) => {
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
        databaseBlobAuditingPolicies: {
            get: {
                'eastus': {
                    [dbId]: {
                        data: databaseBlobAuditingPolicies
                    }
                }
            }
        }
    }
};

describe('dbAuditingEnabled', function() {
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

            dbAuditingEnabled.run(cache, {}, callback);
        });

        it('should give passing result if no databases found for SQL server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No databases found for SQL server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                []
            );

            dbAuditingEnabled.run(cache, {}, callback);
        });

        it('should give failing result if SQL server database does not contain auditing policies', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL server database does not contain auditing policies');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                databases,
                []
            );

            dbAuditingEnabled.run(cache, {}, callback);
        });

        it('should give failing result if Database Auditing is not enabled on the SQL database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Database Auditing is not enabled on the SQL database');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                databases,
                [databaseBlobAuditingPolicies[1]]
            );

            dbAuditingEnabled.run(cache, {}, callback);
        });

        it('should give passing result if Database Auditing is enabled on the SQL database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Database Auditing is enabled on the SQL database');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                databases,
                [databaseBlobAuditingPolicies[0]]
            );

            dbAuditingEnabled.run(cache, {}, callback);
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
                [],
                [],
                [],
                { message: 'unable to query servers'}
            );

            dbAuditingEnabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL server databases', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL server databases');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [],
                [],
                null,
                { message: 'unable to query databases'}
            );

            dbAuditingEnabled.run(cache, {}, callback);
        });
    })
})