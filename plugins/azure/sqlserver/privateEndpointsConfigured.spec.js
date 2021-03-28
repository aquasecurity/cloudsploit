var expect = require('chai').expect;
var privateEndpointsConfigured = require('./privateEndpointsConfigured');

const servers = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server',
        'name': 'test-server',
        'privateEndpointConnections': [
            {
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server/privateEndpointConnections/test-endpoint',
                'provisioningState': 'Ready'
            }
        ],
        'publicNetworkAccess': 'Disabled',
        'location': 'eastus'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server',
        'name': 'test-server',
        'privateEndpointConnections': [
            {
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server/privateEndpointConnections/test-endpoint',
                'provisioningState': 'Ready'
            }
        ],
        'publicNetworkAccess': 'Enabled',
        'location': 'eastus'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server',
        'name': 'test-server',
        'privateEndpointConnections': [],
        'publicNetworkAccess': 'Enabled',
        'location': 'eastus'
    }
];


const createCache = (servers) => {
    let server = {};
    if (servers) {
        server['data'] = servers;
    }
    return {
        servers: {
            listSql: {
                'eastus': server
            }
        }
    };
};

describe('privateEndpointsConfigured', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers', function(done) {
            const cache = createCache([]);
            privateEndpointsConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const cache = createCache(null);
            privateEndpointsConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing results if private endpoints are configured and public network acess is disabled', function(done) {
            const cache = createCache([servers[0]]);
            privateEndpointsConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);

                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Private Endpoints are configured for the SQL Server');

                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('Public Network Access is disabled for the SQL Server');

                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give a failing result if private endpoints are enabled and public network acess is enabled', function(done) {
            const cache = createCache([servers[1]]);
            privateEndpointsConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);

                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Private Endpoints are configured for the SQL Server');

                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('Public Network Access is enabled for the SQL Server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if private endpoints are not configured', function(done) {
            const cache = createCache([servers[2]]);
            privateEndpointsConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Private Endpoints are not configured for the SQL Server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});