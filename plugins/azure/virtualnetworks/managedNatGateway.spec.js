var expect = require('chai').expect;
var managedNatGateway = require('./managedNatGateway');

const natGateways = [
    {
        'name': 'test-nat-gateway',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/natGateways/test-nat-gateway',
        'type': 'Microsoft.Network/natGateways',
        'subnets': [
            {
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/default'
            }
        ]
    }
];

const virtualNetworks = [
    {
        'name': 'test-vnet',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        'type': 'Microsoft.Network/virtualNetworks',
        'subnets': [
            {
                'name': 'default',
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/default',
                'type': 'Microsoft.Network/virtualNetworks/subnets'
            }
        ]
    },
    {
        'name': 'test-vnet-2',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet-2',
        'type': 'Microsoft.Network/virtualNetworks',
        'subnets': [
            {
                'name': 'default',
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet-2/subnets/default',
                'type': 'Microsoft.Network/virtualNetworks/subnets'
            }
        ]
    }
];

const createCache = (virtualNetworks, natGateways) => {
    let network = {};
    let natGateway = {};

    if (virtualNetworks) {
        network['data'] = virtualNetworks;
    }
    if (natGateways) {
        natGateway['data'] = natGateways;
    }

    return {
        virtualNetworks: {
            listAll: {
                'eastus': network
            }
        },
        natGateways: {
            listBySubscription: {
                'eastus': natGateway
            }
        },
    };
};

describe('managedNatGateway', function() {
    describe('run', function() {
        it('should give passing result if No existing virtual networks found', function(done) {
            const cache = createCache([]);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Networks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual networks', function(done) {
            const cache = createCache();
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Networks');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Virtual Network NAT Gateways', function(done) {
            const cache = createCache([virtualNetworks[0]]);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Network NAT Gateways');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if NAT Gateway is configured for Virtual Network', function(done) {
            const cache = createCache([virtualNetworks[0]], [natGateways[0]]);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Network Managed NAT (Network Address Translation) Gateway service is enabled for Virtual Network');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if NAT Gateway is not configured for Virtual Network', function(done) {
            const cache = createCache([virtualNetworks[1]], [natGateways[0]]);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Network Managed NAT (Network Address Translation) Gateway service is disabled for Virtual Network');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});