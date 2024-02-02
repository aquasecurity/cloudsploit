var expect = require('chai').expect;
var noVPNGateways = require('./noVPNgateways');

const resourceGroups = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group',
        'name': 'aqua-resource-group',
        'type': 'Microsoft.Resources/resourceGroups',
        'location': 'eastus'
    }
];

const virtualNetworkGateways = [
    {
        'name': 'test-vpn-gateway',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworkGateways/test-vpn-gateway',
        'type': 'Microsoft.Network/virtualNetworkGateways',
        'gatewayType': 'VPN'
    },
    {
        'name': 'test-expressroute-gateway',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworkGateways/test-expressroute-gateway',
        'type': 'Microsoft.Network/virtualNetworkGateways',
        'gatewayType': 'ExpressRoute'
    }
];

const createCache = (resourceGroups, virtualNetworkGateways) => {
    let groups = {};
    let gateways = {};

    if (resourceGroups) {
        groups['data'] = resourceGroups;
        if (resourceGroups.length && virtualNetworkGateways) {
            gateways[resourceGroups[0].id] = {
                'data': virtualNetworkGateways
            };
        }
    }

    return {
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

describe('noVPNGateways', function() {
    describe('run', function() {
        it('should give passing result if No existing resource groups found', function(done) {
            const cache = createCache([]);
            noVPNGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing resource groups found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for resource groups', function(done) {
            const cache = createCache();
            noVPNGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for resource groups');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if No virtual network gateways found', function(done) {
            const cache = createCache([resourceGroups[0]], []);
            noVPNGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing virtual network gateways found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual network gateways', function(done) {
            const cache = createCache([resourceGroups[0]]);
            noVPNGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual Network Gateways');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if there are VPN gateways', function(done) {
            const cache = createCache([resourceGroups[0]], [virtualNetworkGateways[0]]);
            noVPNGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('gateway is of VPN type');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if there are no VPN gateways', function(done) {
            const cache = createCache([resourceGroups[0]], [virtualNetworkGateways[1]]);
            noVPNGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('gateway is not of VPN type');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
