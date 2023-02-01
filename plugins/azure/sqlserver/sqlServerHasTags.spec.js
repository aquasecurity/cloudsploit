var expect = require('chai').expect;
var sqlServerHasTags = require('./sqlServerHasTags');

 const serverslist = [
    {
        "kind": "v12.0",
        "location": "eastus",
        "tags": { 'key': 'value' },
        "id": "/subscriptions/123/resourceGroups/akhtar-rg/providers/Microsoft.Sql/servers/test-server",
        "name": "test-server",
        "type": "Microsoft.Sql/servers",
        "administratorLogin": "aqua",
        "version": "12.0",
        "state": "Ready",
        "fullyQualifiedDomainName": "test-server.database.windows.net",
        "privateEndpointConnections": [],
        "minimalTlsVersion": "1.1",
        "publicNetworkAccess": "Enabled"
    },
    {
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/akhtar-rg/providers/Microsoft.Sql/servers/test-server",
        "name": "test-server",
        "type": "Microsoft.Sql/servers",
        "administratorLogin": "aqua",
        "version": "12.0",
        "state": "Ready",
        "fullyQualifiedDomainName": "test-server.database.windows.net",
        "privateEndpointConnections": [],
        "publicNetworkAccess": "Enabled"
    }
 ];
const createCache = (serversobj) => {
    return {
        servers: {
            listSql: {
                'eastus': {
                    data: serversobj
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        servers: {
            listSql: {
                'eastus': {}
            }
        }
    };
};

describe('sqlServerHasTags', function() {
    describe('run', function() {
        it('should give passing result if no sql server found', function(done) {
            const cache = createCache([]);
            sqlServerHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for sql server', function(done) {
            const cache = createErrorCache();
            sqlServerHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if sql server has tags', function(done) {
            const cache = createCache([serverslist[0]]);
            sqlServerHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Server has tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if sql server does not have tags', function(done) {
            const cache = createCache([serverslist[1]]);
            sqlServerHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL Server does not have tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});