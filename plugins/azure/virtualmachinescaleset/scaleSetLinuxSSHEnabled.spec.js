var expect = require('chai').expect;
var scaleSetLinuxSSHEnabled = require('./scaleSetLinuxSSHEnabled');

const virtualMachineScaleSets = [
    {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
          "virtualMachineProfile": {
          "osProfile": {
            "linuxConfiguration": {
              "disablePasswordAuthentication": true,
              "ssh": {
                "publicKeys": [
                  {
                    "path": "/home/azureuser/.ssh/authorized_keys",
                    "keyData": ""
                  }
                ]
              },
            },
          },
          "storageProfile": {
            "osDisk": {
              "osType": "Linux",
            },
          }
        }
    },
    {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
          "virtualMachineProfile": {
          "osProfile": {
            "linuxConfiguration": {
              "disablePasswordAuthentication": false
            },
          },
          "storageProfile": {
            "osDisk": {
              "osType": "Linux",
            },
          }
        }
    },
];

const createCache = (virtualMachineScaleSets) => {
    let machine = {};
    if (virtualMachineScaleSets) {
        machine['data'] = virtualMachineScaleSets;
    }
    return {
        virtualMachineScaleSets: {
            listAll: {
                'eastus': machine
            }
        }
    };
};

describe('scaleSetLinuxSSHEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machine scale sets', function(done) {
            const cache = createCache([]);
            scaleSetLinuxSSHEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
            const cache = createCache();
            scaleSetLinuxSSHEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if VM scale set for linux has SSH enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]]);
            scaleSetLinuxSSHEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM scale set for linux has SSH enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if VM scale set for linux does not have SSH enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[1]]);
            scaleSetLinuxSSHEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM scale set for linux does not have SSH enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});