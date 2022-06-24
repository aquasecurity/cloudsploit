var expect = require('chai').expect;
var guestLevelDiagnosticsEnabled = require('./guestLevelDiagnosticsEnabled');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines'
    }
];

const virtualMachinesData = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'resources': [
            {
                'properties': {
                    'settings': {
                        'ladCfg': {
                            'diagnosticMonitorConfiguration': {}
                        }
                    }
                }
            }
        ]
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'resources': [
            {
                'properties': {
                    'settings': {}
                }
            }
        ]
    }
];

const createCache = (virtualMachines, virtualMachineDetails) => {
    let machine = {};
    let machineDetails = {};
    if (virtualMachines) {
        machine['data'] = virtualMachines;
        if (virtualMachineDetails && virtualMachines.length) {
            machineDetails[virtualMachines[0].id]= {
                'data': virtualMachineDetails
            };
        }
    }
    return {
        virtualMachines: {
            listAll: {
                'eastus': machine
            },
            get: {
                'eastus': machineDetails
            }
        }
    };
};

describe('guestLevelDiagnosticsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            guestLevelDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing virtual machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null);
            guestLevelDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine details', function(done) {
            const cache = createCache([virtualMachines[0]], {});
            guestLevelDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('unable to query for virtual machine data');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if VM has guest level diagnostics enabled', function(done) {
            const cache = createCache([virtualMachines[0]], virtualMachinesData[0]);
            guestLevelDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Guest Level Diagnostics are enabled for the virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if VM has guest level diagnostics disabled', function(done) {
            const cache = createCache([virtualMachines[0]], virtualMachinesData[1]);
            guestLevelDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Guest Level Diagnostics are disabled for the virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});