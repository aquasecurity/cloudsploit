var expect = require('chai').expect;
var sqlServerManagedIdentityEnabled = require('./sqlServerManagedIdentity');

const servers = [
    {
        "id": '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server',
        "identity": {
            "type": "UserAssigned"
        }
    },
    {
        "id": '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server-no-identity'
    }
];

const createCache = (servers, serversErr) => {
    return {
        servers: {
            listSql: {
                'eastus': {
                    err: serversErr,
                    data: servers
                }
            }
        }
    };
};

describe('sqlServerManagedIdentityEnabled', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers found', function(done) {
            const cache = createCache([]);
            sqlServerManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const cache = createCache(null, { message: 'unable to query servers' });
            sqlServerManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if managed identity is enabled', function(done) {
            const cache = createCache([servers[0]]);
            sqlServerManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Server has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if managed identity is not enabled', function(done) {
            const cache = createCache([servers[1]]);
            sqlServerManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL Server does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
