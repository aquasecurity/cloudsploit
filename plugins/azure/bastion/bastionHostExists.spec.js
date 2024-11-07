var expect = require('chai').expect;
var bastionHostExist = require('./bastionHostExists');

const listBastionHost = [
    {
      "name": "bastionhost'",
      "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/bastionHosts/bastionhosttenant'",
      "type": "Microsoft.Network/bastionHosts",
      "etag": "w/\\00000000-0000-0000-0000-000000000000\\",
      "location": "West US",
      "sku": {
        "name": "Standard"
      },
      "properties": {
        "provisioningState": "Succeeded",
        "dnsName": "bst-9d89d361-100e-4c01-b92d-466548c476dc.bastion.azure.com",
        "ipConfigurations": [
          {
            "name": "bastionHostIpConfiguration",
            "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/bastionHosts/bastionhosttenant/bastionHostIpConfigurations/bastionHostIpConfiguration",
            "etag": "w/\\00000000-0000-0000-0000-000000000000\\",
            "type": "Microsoft.Network/bastionHosts/bastionHostIpConfigurations",
            "properties": {
              "provisioningState": "Succeeded",
              "privateIPAllocationMethod": "Dynamic",
              "subnet": {
                "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet2/subnets/BastionHostSubnet"
              },
              "publicIPAddress": {
                "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pipName"
              }
            }
          }
        ]
      }
    }
];

const createCache = (listBastionHosts) => {
    return {
        bastionHosts: {
            listAll: {
                'eastus':  { data: listBastionHosts}
            }
        }
    };
};

describe('bastionHostExist', function() {
    describe('run', function() {

        it('should give unknown result if unable to query for azure subscription', function(done) {
            const cache = createCache(null);
            bastionHostExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for bastion host:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if bastion host exist', function(done) {
            const cache = createCache([listBastionHost[0]]);
            bastionHostExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('There are 1 Bastion hosts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no bastion host exist', function(done) {
            const cache = createCache([]);
            bastionHostExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No Bastion hosts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});