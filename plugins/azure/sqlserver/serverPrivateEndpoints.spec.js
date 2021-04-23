var expect = require('chai').expect;
var serverPrivateEndpoints = require('./serverPrivateEndpoints');

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
        'location': 'eastus'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server',
        'name': 'test-server',
        'privateEndpointConnections': [],
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

describe('serverPrivateEndpoints', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers', function(done) {
            const cache = createCache([]);
            serverPrivateEndpoints.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const cache = createCache(null);
            serverPrivateEndpoints.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if private endpoints are configured', function(done) {
            const cache = createCache([servers[0]]);
            serverPrivateEndpoints.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Private Endpoints are configured for the SQL Server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if private endpoints are not configured', function(done) {
            const cache = createCache([servers[1]]);
            serverPrivateEndpoints.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Private Endpoints are not configured for the SQL Server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});