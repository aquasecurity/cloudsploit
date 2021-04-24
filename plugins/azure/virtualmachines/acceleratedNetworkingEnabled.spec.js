var expect = require('chai').expect;
var acceleratedNetworkingEnabled = require('./acceleratedNetworkingEnabled');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'networkProfile': {
            'networkInterfaces': [
                {
                    'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/networkInterfaces/test-network-interface'
                }
            ]
        }
    }
];

const networkInterfaces = [
    {
        'name': 'test-network-interface',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/networkInterfaces/test-network-interface',
        'location': 'eastus',
        'type': 'Microsoft.Network/networkInterfaces',
        'enableAcceleratedNetworking': true
    },
    {
        'name': 'test-network-interface',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/networkInterfaces/test-network-interface',
        'location': 'eastus',
        'type': 'Microsoft.Network/networkInterfaces',
        'enableAcceleratedNetworking': false
    }
];

const createCache = (virtualMachines, networkInterfaces) => {
    let machine = {};
    let interface = {};
    if (virtualMachines) {
        machine['data'] = virtualMachines;
    }
    if (interface) {
        interface['data'] = networkInterfaces;
    }
    return {
        virtualMachines: {
            listAll: {
                'eastus': machine
            }
        },
        networkInterfaces: {
            listAll: {
                'eastus': interface
            }
        }
    };
};

describe('acceleratedNetworkingEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([], null);
            acceleratedNetworkingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null, null);
            acceleratedNetworkingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtualMachines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if no network interfaces found', function(done) {
            const cache = createCache([virtualMachines[0]], []);
            acceleratedNetworkingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for network interfaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for network interfaces', function(done) {
            const cache = createCache([virtualMachines[0]], null);
            acceleratedNetworkingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for network interfaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if accelerated networking is enabled', function(done) {
            const cache = createCache([virtualMachines[0]], [networkInterfaces[0]]);
            acceleratedNetworkingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Accelerated Networking is enabled on Azure Virtual Machine(VM)');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if accelerated networking is not enabled', function(done) {
            const cache = createCache([virtualMachines[0]], [networkInterfaces[1]]);
            acceleratedNetworkingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Accelerated Networking is not enabled on Azure Virtual Machine(VM)');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});