var expect = require('chai').expect;
var networkGatewaysUsage = require('./noNetworkGatewaysInUse');

const virtualNetworks = [
    {
        'name': 'test-vnet',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        'type': 'Microsoft.Network/virtualNetworks',
        'location': 'eastus',
        'subnets': [
            {
                'name': 'GatewaySubnet',
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/GatewaySubnet',
                'properties': {
                    'ipConfigurations': [
                        {
                            'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworkGateways/test-gateway/ipConfigurations/default'
                        }
                    ],
                }
            }
        ],
    }
];

const resourceGroups = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group',
        'name': 'aqua-resource-group',
        'type': 'Microsoft.Resources/resourceGroups',
        'location': 'eastus'
    }
];

const networkGateways = [
    {
        'name': 'test-gateway',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworkGateways/test-gateway',
        'type': 'Microsoft.Network/virtualNetworkGateways',
    }
];

const createCache = (virtualNetworks, resourceGroups, networkGateways) => {
    let networks = {};
    let groups = {};
    let gateways = {};

    if (virtualNetworks) {
        networks['data'] = virtualNetworks;
    }

    if (resourceGroups) {
        groups['data'] = resourceGroups;
        if (resourceGroups.length && networkGateways) {
            gateways[resourceGroups[0].id] = {
                'data': networkGateways
            };
        }
    }

    return {
        virtualNetworks: {
            listAll: {
                'eastus': networks
            }
        },
        resourceGroups: {
            list: {
                'eastus': groups
            }
        },
        virtualNetworkGateways: {
            listByResourceGroup: {
                'eastus': gateways
            }
        },
    };
};

describe('networkGatewaysUsage', function() {
    describe('run', function() {
        it('should give passing result if No existing Virtual Networks found', function(done) {
            const cache = createCache([]);
            networkGatewaysUsage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Networks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Virtual Networks', function(done) {
            const cache = createCache();
            networkGatewaysUsage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Networks');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if No existing resource groups found', function(done) {
            const cache = createCache([virtualNetworks[0]], []);
            networkGatewaysUsage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing resource groups found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for resource groups', function(done) {
            const cache = createCache([virtualNetworks[0]]);
            networkGatewaysUsage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for resource groups');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if virtual network is not using network gateways', function(done) {
            const cache = createCache([virtualNetworks[0]], [resourceGroups[0]], []);
            networkGatewaysUsage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual network is not using network gateways');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if virtual network is using network gateways', function(done) {
            const cache = createCache([virtualNetworks[0]], [resourceGroups[0]], [networkGateways[0]]);
            networkGatewaysUsage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual network is using network gateways');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});