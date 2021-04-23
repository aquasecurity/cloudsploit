var expect = require('chai').expect;
var pitrBackupEnabled = require('./pitrBackupEnabled');

const servers = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server',
        'name': 'test-server'
    }
];

const databases = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server/databases/test-db',
        'name': 'test-db'
    }
];

const policies = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server/databases/test-db/backupShortTermRetentionPolicies/default',
        'name': 'default',
        'retentionDays': 2
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server/databases/test-db/backupShortTermRetentionPolicies/default',
        'name': 'default',
        'retentionDays': 14
    }
];


const createCache = (servers, databases, policies) => {
    let db = {};
    if (servers.length > 0) {
        db[servers[0].id] = {
            data: databases
        };
    }

    let retentionPolicy = {};
    if (databases.length > 0) {
        retentionPolicy[databases[0].id] = {
            data: policies
        };
    }

    return {
        servers: {
            listSql: {
                'eastus': {
                    data: servers
                }
            }
        },
        databases: {
            listByServer: {
                'eastus': db
            }
        },
        backupShortTermRetentionPolicies:{
            listByDatabase: {
                'eastus': retentionPolicy
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key === 'server') {
        return {
            servers: {
                listSql: {
                    'eastus': {}
                }
            }
        };
    } else if (key === 'database') {
        return {
            servers: {
                listSql: {
                    'eastus': {
                        data: [servers[0]]
                    }
                }
            },
            databases: {
                listByServer: {
                    'eastus': {}
                }
            }
        };
    } else {
        const serverId = (servers && servers.length) ? servers[0].id : null;
        return {
            servers: {
                listSql: {
                    'eastus': {
                        data: [servers[0]]
                    }
                }
            },
            databases: {
                listByServer: {
                    'eastus': {
                        [serverId]: {
                            data: [databases[0]]
                        }
                    }
                },
                shortTermRetentionPolicy:{
                    'eastus': {}
                }
            }
        };
    }
};

describe('pitrBackupEnabled', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers', function(done) {
            const cache = createCache([], [], []);
            pitrBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        
        it('should give passing result if no SQL databases', function(done) {
            const cache = createCache([servers[0]], [], []);
            pitrBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No databases found for SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no retention policies', function(done) {
            const cache = createCache([servers[0]], [databases[0]], []);
            pitrBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No retention policies found for SQL database');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const cache = createErrorCache('server');
            pitrBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for SQL databases', function(done) {
            const cache = createErrorCache('database');
            pitrBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL server databases:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for retention policies', function(done) {
            const cache = createErrorCache('policy');
            pitrBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL database retention policies:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if database has desired retention period set', function(done) {
            const cache = createCache([servers[0]], [databases[0]], [policies[1]]);
            pitrBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Database is configured to retain backups for 14 of 7 days desired limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if database does not have desired retention period set', function(done) {
            const cache = createCache([servers[0]], [databases[0]], [policies[0]]);
            pitrBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL Database is configured to retain backups for 2 of 7 days desired limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});