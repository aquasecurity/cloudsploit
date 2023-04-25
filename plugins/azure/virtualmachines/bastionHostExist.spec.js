var expect = require('chai').expect;
var bastionHostExist = require('./bastionHostExist');

const listSubscriptions = [
   {
      "id": "/subscriptions/291bba3f-e0a5-47bc-a099-3bdcb2a50a05",
      "subscriptionId": "291bba3f-e0a5-47bc-a099-3bdcb2a50a05",
      "tenantId": "31c75423-32d6-4322-88b7-c478bdde4858",
      "displayName": "Example Subscription",
      "state": "Enabled",
      "subscriptionPolicies": {
        "locationPlacementId": "Internal_2014-09-01",
        "quotaId": "Internal_2014-09-01",
        "spendingLimit": "Off"
      },
      "authorizationSource": "RoleBased",
      "managedByTenants": [
        {
          "tenantId": "8f70baf1-1f6e-46a2-a1ff-238dac1ebfb7"
        }
      ],
      "tags": {
        "tagKey1": "tagValue1",
        "tagKey2": "tagValue2"
      }
    },
];

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

const createCache = (listSubscription, listBastionHosts) => {
   var subId =  listSubscription && listSubscription.length > 0 ? listSubscription[0].id : null;
    return {
        subscriptions: {
            listSubscriptions: {
                'global': { data: listSubscription }
            }
        },
        bastionHost: {
            listAll: {
                'global': {
                    [subId]: { data: listBastionHosts}
                }
            }
        }
    };
};

describe('bastionHostExist', function() {
    describe('run', function() {
        it('should give passing result if no subscription exist', function(done) {
            const cache = createCache([]);
            bastionHostExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Azure subscription exist');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for azure subscription', function(done) {
            const cache = createCache(null);
            bastionHostExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for subscriptions');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for bastion host', function(done) {
            const cache = createCache([listSubscriptions[0]]);
            bastionHostExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for bastion host:');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if subscription has bastion host', function(done) {
            const cache = createCache([listSubscriptions[0]], [listBastionHost[0]]);
            bastionHostExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Azure subscription have bastion host');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if no bastion host exist', function(done) {
            const cache = createCache([listSubscriptions[0]], []);
            bastionHostExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Azure subscription does not have bastion host');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});