var expect = require('chai').expect;
var vmssApplicationGatewayEnabled = require('./vmssApplicationGatewayEnabled');

const virtualMachineScaleSets = [
    {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'virtualMachineProfile': {
            "networkProfile": {
            "networkInterfaceConfigurations": [
              { "properties": {
                    "ipConfigurations": [
                        {
                        
                        "properties": {                      
                            "applicationGatewayBackendAddressPools": [
                            {
                                "id": "/subscriptions/123456789/resourceGroups/test-rg/providers/Microsoft.Network/applicationGateways/test-vmss-gateway/backendAddressPools/test-vmss-gateway-backendpool01"
                            }
                            ]
                        }
                        }
                    ]
                  }
                }
            ]
          }
            
        }
    },
     {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'virtualMachineProfile': {
            "networkProfile": {
            "networkInterfaceConfigurations": [
              {   "properties": {
                    "ipConfigurations": [
                        {
                        "properties": {                      
                        }
                        }
                    ]
                  }
                }
            ]
          }
        }
    }
    
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

describe('vmssApplicationGatewayEnabled', function() {
   describe('run', function() {
       it('should give passing result if no virtual machine scale sets', function(done) {
           const cache = createCache([]);
           vmssApplicationGatewayEnabled.run(cache, {}, (err, results) => {
               expect(results.length).to.equal(1);
               expect(results[0].status).to.equal(0);
               expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found');
               expect(results[0].region).to.equal('eastus');
               done();
           });
       });

       it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
           const cache = createCache();
           vmssApplicationGatewayEnabled.run(cache, {}, (err, results) => {
               expect(results.length).to.equal(1);
               expect(results[0].status).to.equal(3);
               expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets:');
               expect(results[0].region).to.equal('eastus');
               done();
           });
       });

       it('should give passing result if Application Gateway is enabled to VMSS', function(done) {
           const cache = createCache([virtualMachineScaleSets[0]]);
           vmssApplicationGatewayEnabled.run(cache, {}, (err, results) => {
               expect(results.length).to.equal(1);
               expect(results[0].status).to.equal(0);
               expect(results[0].message).to.include('Virtual Machine Scale Set has application gateway enabled');
               expect(results[0].region).to.equal('eastus');
               done();
           });
       });

       it('should give failing result if Application Gateway is not enabled for VMSS', function(done) {
           const cache = createCache([virtualMachineScaleSets[1]]);
           vmssApplicationGatewayEnabled.run(cache, {}, (err, results) => {
               expect(results.length).to.equal(1);
               expect(results[0].status).to.equal(2);
               expect(results[0].message).to.include('Virtual Machine Scale Set does not have application gateway enabled');
               expect(results[0].region).to.equal('eastus');
               done();
           });
       });
   });
});
