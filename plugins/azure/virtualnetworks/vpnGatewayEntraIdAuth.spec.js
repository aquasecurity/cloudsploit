var expect = require('chai').expect;
var vpnGatewayEntraIdAuth = require('./vpnGatewayEntraIdAuth');

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
        'name': 'test-gateway',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworkGateways/test-gateway',
        'type': 'Microsoft.Network/virtualNetworkGateways',
        'gatewayType': 'Vpn',
        'vpnClientConfiguration': {
            'vpnAuthenticationTypes': ['AAD']
        }
    },
    {
        'name': 'test-gateway',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworkGateways/test-gateway',
        'type': 'Microsoft.Network/virtualNetworkGateways',
        'gatewayType': 'Vpn',
        'vpnClientConfiguration': {
            'vpnAuthenticationTypes': ['AAD', 'Certificate']
        }
    },
    {
        'name': 'test-gateway',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworkGateways/test-gateway',
        'type': 'Microsoft.Network/virtualNetworkGateways',
        'gatewayType': 'Vpn'
    },
    {
        'name': 'test-gateway',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworkGateways/test-gateway',
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
        }
    };
};

describe('vpnGatewayEntraIdAuth', function () {
    describe('run', function () {
        it('should give passing result if no resource groups found', function (done) {
            const cache = createCache([], null);
            vpnGatewayEntraIdAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing resource groups found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for resource groups', function (done) {
            const cache = createCache(null, null);
            vpnGatewayEntraIdAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for resource groups');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no VPN gateways found', function (done) {
            const cache = createCache(resourceGroups, []);
            vpnGatewayEntraIdAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing VPN gateways found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if VPN gateway uses Entra ID authentication only', function (done) {
            const cache = createCache(resourceGroups, [virtualNetworkGateways[0]]);
            vpnGatewayEntraIdAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VPN gateway point-to-site configuration is using Entra ID authentication only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if VPN gateway uses more than one authentication type', function (done) {
            const cache = createCache(resourceGroups, [virtualNetworkGateways[1]]);
            vpnGatewayEntraIdAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VPN gateway point-to-site configuration is not using Entra ID authentication only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if VPN gateway does not have point-to-site configuration', function (done) {
            const cache = createCache(resourceGroups, [virtualNetworkGateways[2]]);
            vpnGatewayEntraIdAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VPN gateway does not have point-to-site configuration enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if gateway is not a VPN gateway', function (done) {
            const cache = createCache(resourceGroups, [virtualNetworkGateways[3]]);
            vpnGatewayEntraIdAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing VPN gateways found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
