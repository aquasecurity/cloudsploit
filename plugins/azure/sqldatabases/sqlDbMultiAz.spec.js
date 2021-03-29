var expect = require('chai').expect;
var sqlDbMultiAz = require('./sqlDbMultiAz');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
    }
];

const databases = [
    {
       "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/master",
       "zoneRedundant": true,
    },
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/master",
        "zoneRedundant": false,
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
    }
};

describe('sqlDbMultiAz', function() {
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

            sqlDbMultiAz.run(cache, {}, callback);
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

            sqlDbMultiAz.run(cache, {}, callback);
        });

        it('should give failing result if SQL Database does not have zone redundancy enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL Database does not have zone redundancy enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [databases[1]],
            );

            sqlDbMultiAz.run(cache, {}, callback);
        });

        it('should give passing result if SQL Database has zone redundancy enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Database has zone redundancy enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [databases[0]]
            );

            sqlDbMultiAz.run(cache, {}, callback);
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
                { message: 'unable to query servers'}
            );

            sqlDbMultiAz.run(cache, {}, callback);
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
                null,
                { message: 'unable to query databases'}
            );

            sqlDbMultiAz.run(cache, {}, callback);
        });
    })
})