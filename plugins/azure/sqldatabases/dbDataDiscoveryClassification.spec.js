var expect = require('chai').expect;
var dataDiscoveryAndClassification = require('./dbDataDiscoveryClassification');

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

const sensitivityLabels = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/currentSensitivityLabels/1",
    },
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-database/currentSensitivityLabels/2",
    },
];

const createCache = (servers, databases, sensitivityLabels, serversErr, databasesErr, sensitivityLabelsErr) => {
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
        currentSensitivityLabels: {
            list: {
                'eastus': {
                    [databaseId]: {
                        err: sensitivityLabelsErr,
                        data: sensitivityLabels
                    }
                }
            }
        }
    };
};

describe('dataDiscoveryAndClassification', function() {
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
                sensitivityLabels
            );

            dataDiscoveryAndClassification.run(cache, {}, callback);
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
                sensitivityLabels
            );

            dataDiscoveryAndClassification.run(cache, {}, callback);
        });

        it('should give passing result if Data discovery and classification is being used for the database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Database is using data discovery and classification');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                sensitivityLabels
            );

            dataDiscoveryAndClassification.run(cache, {}, callback);
        });

        it('should give failing result if Data discovery and classification is not being used for the database', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL Database is not using data discovery and classification');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                []
            );

            dataDiscoveryAndClassification.run(cache, {}, callback);
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
                sensitivityLabels,
                { message: 'unable to query servers' }
            );

            dataDiscoveryAndClassification.run(cache, {}, callback);
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
                sensitivityLabels,
                null,
                { message: 'unable to query databases' }
            );

            dataDiscoveryAndClassification.run(cache, {}, callback);
        });

        it('should give unknown result if unable to check data discovery and classification', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Unable to query data discovery and classification information: ');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers,
                databases,
                sensitivityLabels,
                null,
                null,
                { message: 'unable to check sensitivity labels' }
            );

            dataDiscoveryAndClassification.run(cache, {}, callback);
        });
    });
});
