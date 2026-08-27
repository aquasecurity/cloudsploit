var expect = require('chai').expect;
var subnetNetworkSecurityGroup = require('./subnetNetworkSecurityGroup');

const virtualNetworks = [
    {
        'name': 'test-vnet',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        'type': 'Microsoft.Network/virtualNetworks',
        'location': 'eastus',
        'subnets': [
            {
                'name': 'default',
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/default',
                'properties': {
                    'networkSecurityGroup': {
                        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/networkSecurityGroups/test-nsg'
                    }
                }
            }
        ]
    },
    {
        'name': 'test-vnet',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        'type': 'Microsoft.Network/virtualNetworks',
        'location': 'eastus',
        'subnets': [
            {
                'name': 'default',
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/default',
                'properties': {}
            }
        ]
    },
    {
        'name': 'test-vnet',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        'type': 'Microsoft.Network/virtualNetworks',
        'location': 'eastus',
        'subnets': [
            {
                'name': 'GatewaySubnet',
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/GatewaySubnet',
                'properties': {}
            }
        ]
    },
    {
        'name': 'test-vnet',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        'type': 'Microsoft.Network/virtualNetworks',
        'location': 'eastus',
        'subnets': [
            {
                'name': 'AzureBastionSubnet',
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/AzureBastionSubnet',
                'properties': {}
            }
        ]
    }
];

const createCache = (virtualNetworks) => {
    return {
        virtualNetworks: {
            listAll: {
                'eastus': {
                    data: virtualNetworks
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        virtualNetworks: {
            listAll: {
                'eastus': {}
            }
        }
    };
};

describe('subnetNetworkSecurityGroup', function () {
    describe('run', function () {
        it('should give passing result if no virtual networks found', function (done) {
            const cache = createCache([]);
            subnetNetworkSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Networks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual networks', function (done) {
            const cache = createErrorCache();
            subnetNetworkSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Networks');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if subnet has a network security group associated', function (done) {
            const cache = createCache([virtualNetworks[0]]);
            subnetNetworkSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Subnet has a network security group associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if subnet does not have a network security group associated', function (done) {
            const cache = createCache([virtualNetworks[1]]);
            subnetNetworkSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Subnet does not have a network security group associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should not evaluate subnets that do not support network security groups', function (done) {
            const cache = createCache([virtualNetworks[2]]);
            subnetNetworkSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing subnets found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if bastion subnet does not have a network security group associated', function (done) {
            const cache = createCache([virtualNetworks[3]]);
            subnetNetworkSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Subnet does not have a network security group associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
