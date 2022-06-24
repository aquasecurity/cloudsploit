var expect = require('chai').expect;
var virtualNetworkPeering = require('./virtualNetworkPeering');

const virtualNetworks = [
    {
        'name': 'test-vnet',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        'type': 'Microsoft.Network/virtualNetworks',
    }
];

const virtualNetworkPeerings = [
    {
        'name': 'test-peer',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet/virtualNetworkPeerings/test-peer',
        'type': 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings',
        'remoteVirtualNetwork': {
            'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet-2'
        }
    }
];

const createCache = (virtualNetworks, virtualNetworkPeerings) => {
    let network = {};
    let peer = {};

    if (virtualNetworks) {
        network['data'] = virtualNetworks;
        if (virtualNetworks.length && virtualNetworkPeerings) {
            peer[virtualNetworks[0].id] = {
                'data': virtualNetworkPeerings
            };
        }
    }

    return {
        virtualNetworks: {
            listAll: {
                'eastus': network
            }
        },
        virtualNetworkPeerings: {
            list: {
                'eastus': peer
            }
        },
    };
};

describe('virtualNetworkPeering', function() {
    describe('run', function() {
        it('should not run plugin if subscription id is not provided and opt in is set to false', function(done) {
            const cache = createCache([]);
            virtualNetworkPeering.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should give passing result if No existing virtual networks found', function(done) {
            const cache = createCache([]);
            virtualNetworkPeering.run(cache, { enable_virtual_network_peering: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Networks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual networks', function(done) {
            const cache = createCache();
            virtualNetworkPeering.run(cache, { enable_virtual_network_peering: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Networks');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if No existing Virtual Network Peerings found', function(done) {
            const cache = createCache([virtualNetworks[0]], []);
            virtualNetworkPeering.run(cache, { enable_virtual_network_peering: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Network Peerings found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Virtual Network Peerings', function(done) {
            const cache = createCache([virtualNetworks[0]]);
            virtualNetworkPeering.run(cache, { enable_virtual_network_peering: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Network Peerings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if subscription is whitelisted', function(done) {
            const cache = createCache([virtualNetworks[0]], [virtualNetworkPeerings[0]]);
            virtualNetworkPeering.run(cache, { whitelisted_peering_subscriptions: '123' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual network is connected with a virtual network in whitelisted subscription');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if subscription is not whitelisted', function(done) {
            const cache = createCache([virtualNetworks[0]], [virtualNetworkPeerings[0]]);
            virtualNetworkPeering.run(cache, { enable_virtual_network_peering: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Vitual network has peering with these unknown subscriptions: 123');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});