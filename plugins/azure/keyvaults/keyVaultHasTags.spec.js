var expect = require('chai').expect;
var keyVaultHasTags = require('./keyVaultHasTags');

const listVaults = [
    {
        "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.KeyVault/vaults/xZbb",  
        "name": "xZbb",
        "type": "Microsoft.KeyVault/vaults",
        "location": "eastus",
        "tags": { "key": "vault" },
        "sku": {
          "family": "A",
          "name": "Standard"
        },
        "tenantId": "2d4f0836-5935-47f5-954c-14e713119ac2",
        "networkAcls": {
          "bypass": "None",
          "defaultAction": "Deny",
          "ipRules": [],
          "virtualNetworkRules": [
            {
              "id": "/subscriptions/1234/resourcegroups/akhtar-rg/providers/microsoft.network/virtualnetworks/akhtar-rg-vnet/subnets/default",
              "ignoreMissingVnetServiceEndpoint": false
            }
          ]
        },
        "privateEndpointConnections": [
          {
            "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.KeyVault/vaults/xZbb/privateEndpointConnections/sadeed",
            "properties": {
              "provisioningState": "Succeeded",
              "privateEndpoint": {
                "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.Network/privateEndpoints/sadeed"
              },
              "privateLinkServiceConnectionState": {
                "status": "Approved",
                "actionsRequired": "None"
              }
            }
          }
        ],
    },
    {
        "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.KeyVault/vaults/xZbb",  
        "name": "xZbb",
        "type": "Microsoft.KeyVault/vaults",
        "location": "eastus",
        "tags": {},
        "sku": {
          "family": "A",
          "name": "Standard"
        },
        "tenantId": "2d4f0836-5935-47f5-954c-14e713119ac2",
        "networkAcls": {
          "bypass": "AzureServices",
          "defaultAction": "Allow",
          "ipRules": [],
          "virtualNetworkRules": [
            {
              "id": "/subscriptions/1234/resourcegroups/akhtar-rg/providers/microsoft.network/virtualnetworks/akhtar-rg-vnet/subnets/default",
              "ignoreMissingVnetServiceEndpoint": false
            }
          ]
        },
        "privateEndpointConnections": [
          {
            "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.KeyVault/vaults/xZbb/privateEndpointConnections/sadeed",
            "properties": {
              "provisioningState": "Succeeded",
              "privateEndpoint": {
                "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.Network/privateEndpoints/sadeed"
              },
              "privateLinkServiceConnectionState": {
                "status": "Approved",
                "actionsRequired": "None"
              }
            }
          }
        ],
    },
];

const createCache = (err, list) => {
    return {
        vaults: {
            list: {
                'eastus': {
                    err: err,
                    data: list
                }
            },
        }
    }
};

describe('keyVaultHasTags', function() {
    describe('run', function() {
        it('should give passing result if no key vaults found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            keyVaultHasTags.run(createCache(null, []), {}, callback);
        });

        it('should give unkown result if Unable to query for Key Vaults', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            keyVaultHasTags.run(createCache(null, null), {}, callback);
        });

        it('should give passing result if key vault  has tags', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key Vault has tags associated');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            keyVaultHasTags.run(createCache(null, [listVaults[0]]), {}, callback);
        });

        it('should give failing result if key vault does not have tags', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vault does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            keyVaultHasTags.run(createCache(null, [listVaults[1]]), {}, callback);
        })
    })
});