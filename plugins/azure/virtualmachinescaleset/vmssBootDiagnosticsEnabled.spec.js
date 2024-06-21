var expect = require('chai').expect;
var vmssBootDiagnosticsEnabled = require('./vmssBootDiagnosticsEnabled');

const vmScaleSet = [
    { "name": 'test',
      "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/virtualMachineScaleSets/test",
      "type": "Microsoft.Compute/virtualMachineScaleSets",
      "location": "centralus",
      "virtualMachineProfile": {
    "osProfile": {
      "computerNamePrefix": 'aks-agentpool-209948-vmss',
      "adminUsername": 'azureuser',
      "secrets": [],
      "allowExtensionOperations": true,
      "requireGuestProvisionSignal": true
    },
    "storageProfile": {
      "osDisk": ["Object"],
      "imageReference": ["Object"],
      "diskControllerType": 'SCSI'
    },
    "diagnosticsProfile": { 
        "bootDiagnostics": {
            "enabled": true
        }
    },
  },
    },
    { "name": 'test',
      "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/virtualMachineScaleSets/test",
      "type": "Microsoft.Compute/virtualMachineScaleSets",
      "location": "centralus",
      "tags": {},
      "virtualMachineProfile": {
        "osProfile": {
        "computerNamePrefix": 'aks-agentpool-209948-vmss',
        "adminUsername": 'azureuser',
        "secrets": [],
        "allowExtensionOperations": true,
        "requireGuestProvisionSignal": true
    },
    "storageProfile": {
      "osDisk": ["Object"],
      "imageReference": ["Object"],
      "diskControllerType": 'SCSI'
    },
    "diagnosticsProfile": { 
    },
  },
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

describe('vmssBootDiagnosticsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machine scale sets', function(done) {
                const cache = createCache([]);
                vmssBootDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found');
                expect(results[0].region).to.equal('eastus');
                done()
                });
        });

        it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
            const cache = createCache();
            vmssBootDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if boot diagnostics are enabled for virtual machine scale sets', function(done) {
            const cache = createCache([vmScaleSet[0]]);
            vmssBootDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine Scale Set has boot diagnostics enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            });
        });

        it('should give failing result if boot diagnostics are disabled for virtual machine scale sets', function(done) {
            const cache = createCache([vmScaleSet[1]]);
            vmssBootDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Machine Scale Set does not have boot diagnostics enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            });
        })
    })
});