var expect = require('chai').expect;
var dbDiagnosticLoggingEnabled = require('./dbDiagnosticLoggingEnabled');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
    }
];

const databases = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database",
        "name": "test-database"
    }
];

const diagnosticSettings = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/diagnosticSettings/1",
        "logs": [
            { "category": "SQLInsights", "enabled": true },
            { "category": "Errors", "enabled": true },
            { "category": "Timeouts", "enabled": true },
            { "category": "Blocks", "enabled": true },
            { "category": "Deadlocks", "enabled": true }
        ],
        "metrics": [
            { "category": "Basic", "enabled": true },
            { "category": "InstanceAndAppAdvanced", "enabled": true },
            { "category": "WorkloadManagement", "enabled": true },

        ]
    }
];

const createCache = (servers, databases, diagnosticSettings, serversErr, databasesErr, diagnosticSettingsErr) => {
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
        diagnosticSettings: {
            listByDatabase: {
                'eastus': {
                    [databaseId]: {
                        err: diagnosticSettingsErr,
                        data: diagnosticSettings
                    }
                }
            }
        }
    };
};

describe('dbDiagnosticLoggingEnabled', function() {
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
                diagnosticSettings
            );

            dbDiagnosticLoggingEnabled.run(cache, {}, callback);
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
                diagnosticSettings
            );

            dbDiagnosticLoggingEnabled.run(cache, {}, callback);
        });

        it('should give passing result if diagnostic settings configured with minimum requirements', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL database has diagnostic logs/metrics enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                diagnosticSettings
            );

            dbDiagnosticLoggingEnabled.run(cache, {}, callback);
        });

        it('should give failing result if diagnostic settings not configured for the database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL database does not have diagnostic logs/metrics enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                []
            );

            dbDiagnosticLoggingEnabled.run(cache, {}, callback);
        });

        it('should give failing result if diagnostic settings not configured with minimum requirements', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL database does not have diagnostic logs/metrics enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                [
                    {
                        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/diagnosticSettings/1",
                        "metrics": [
                            { "category": "SQLInsights", "enabled": true },
                            { "category": "Errors", "enabled": false } // Errors is required, but not enabled
                        ],
                        "logs": [
                            { "category": "Timeouts", "enabled": true },
                            { "category": "Blocks", "enabled": true }
                        ]
                    }
                ]
            );

            dbDiagnosticLoggingEnabled.run(cache, {}, callback);
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
                diagnosticSettings,
                { message: 'unable to query servers' }
            );

            dbDiagnosticLoggingEnabled.run(cache, {}, callback);
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
                diagnosticSettings,
                null,
                { message: 'unable to query databases' }
            );

            dbDiagnosticLoggingEnabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query diagnostic settings', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query SQL database diagnostic settings');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                [],
                null,
                null,
                { message: 'unable to query diagnostic settings' }
            );

            dbDiagnosticLoggingEnabled.run(cache, {}, callback);
        });
    });
});
