var expect = require('chai').expect;
var sqlServerTlsVersion = require('./sqlServerTlsVersion');

const servers = [
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
    }
};

describe('sqlServerTlsVersion', function() {
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

            sqlServerTlsVersion.run(cache, {}, callback);
        });

        it('should give failing result if SQL server is using TLS version less than desired TLS version', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('less than desired TLS version');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [servers[0]],
            );

            sqlServerTlsVersion.run(cache, { sql_server_min_tls_version: '1.2' }, callback);
        });

        it('should give failing result if SQL server allows all TLS versions', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL server allows all TLS versions');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [servers[1]],
            );

            sqlServerTlsVersion.run(cache, { sql_server_min_tls_version: '1.2' }, callback);
        });

        it('should give passing result if SQL server is using TLS version equal to or higher than desired TLS version', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('equal to or higher than desired TLS version');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [servers[0]]
            );

            sqlServerTlsVersion.run(cache, { sql_server_min_tls_version: '1.0' }, callback);
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
                servers,
                { message: 'unable to query servers'}
            );

            sqlServerTlsVersion.run(cache, {}, callback);
        });
    })
})