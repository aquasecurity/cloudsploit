var expect = require('chai').expect;
var noGatewayConnections = require('./noGatewayConnections');

const resourceGroups = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group',
        'name': 'aqua-resource-group',
        'type': 'Microsoft.Resources/resourceGroups',
        'location': 'eastus'
    }
];

const networkGatewayConnections = [
    {
        'name': 'test-connection',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/connections/test-connection',
        'type': 'Microsoft.Network/connections',
        'virtualNetworkGateway1': {
            'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworkGateways/test-gateway'
        },
        'virtualNetworkGateway2': {
            'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworkGateways/test-gateway-2'
        }
    }
];

const createCache = (resourceGroups, networkGatewayConnections) => {
    let groups = {};
    let connections = {};

    if (resourceGroups) {
        groups['data'] = resourceGroups;
        if (resourceGroups.length && networkGatewayConnections) {
            connections[resourceGroups[0].id] = {
                'data': networkGatewayConnections
            };
        }
    }

    return {
        resourceGroups: {
            list: {
                'eastus': groups
            }
        },
         networkGatewayConnections: {
            listByResourceGroup: {
                'eastus': connections
            }
        },
    };
};

describe('noGatewayConnections', function() {
    describe('run', function() {
        it('should give passing result if No existing resource groups found', function(done) {
            const cache = createCache([]);
            noGatewayConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing resource groups found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for resource groups', function(done) {
            const cache = createCache();
            noGatewayConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for resource groups');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if No network gateway connections found', function(done) {
            const cache = createCache([resourceGroups[0]], []);
            noGatewayConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No connections found for network gateways');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for network gateway connections', function(done) {
            const cache = createCache([resourceGroups[0]]);
            noGatewayConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for network gateway connections');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if there are network gateway connections', function(done) {
            const cache = createCache([resourceGroups[0]], [networkGatewayConnections[0]]);
            noGatewayConnections.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('test-gateway has an established connection with test-gateway-2');
                
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('test-gateway-2 has an established connection with test-gateway');

                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});