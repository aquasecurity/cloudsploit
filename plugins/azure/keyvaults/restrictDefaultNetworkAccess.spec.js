var expect = require('chai').expect;
var auth = require('./restrictDefaultNetworkAccess');

const listVaults = [
  {
    "id": "/subscriptions/1234/resourceGroups/testrg/providers/Microsoft.KeyVault/vaults/xZbb",
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
        "id": "/subscriptions/1234/resourceGroups/testrg/providers/Microsoft.KeyVault/vaults/xZbb/privateEndpointConnections/sadeed",
        "properties": {
          "provisioningState": "Succeeded",
          "privateEndpoint": {
            "id": "/subscriptions/1234/resourceGroups/testrg/providers/Microsoft.Network/privateEndpoints/sadeed"
          },
          "privateLinkServiceConnectionState": {
            "status": "Approved",
            "actionsRequired": "None"
          }
        }
      }
    ],
    "accessPolicies": [
      {
        "tenantId": "2d4f0836-5935-47f5-954c-14e713119ac2",
        "objectId": "d198cb4d-de06-40ff-8fc4-4f643fbeabc5",
        "permissions": {
          "keys": [
            "Get",
            "List",
            "Update",
            "Create",
            "Import",
            "Delete",
            "Recover",
            "Backup",
            "Restore",
            "GetRotationPolicy",
            "SetRotationPolicy",
            "Rotate"
          ],
          "secrets": [
            "Get",
            "List",
            "Set",
            "Delete",
            "Recover",
            "Backup",
            "Restore"
          ],
          "certificates": [
            "Get",
            "List",
            "Update",
            "Create",
            "Import",
            "Delete",
            "Recover",
            "Backup",
            "Restore",
            "ManageContacts",
            "ManageIssuers",
            "GetIssuers",
            "ListIssuers",
            "SetIssuers",
            "DeleteIssuers"
          ]
        }
      }
    ],
    "enabledForDeployment": false,
    "enabledForDiskEncryption": false,
    "enabledForTemplateDeployment": false,
    "enableSoftDelete": true,
    "softDeleteRetentionInDays": 90,
    "enableRbacAuthorization": false,
    "vaultUri": "https://xzbb.vault.azure.net/",
    "provisioningState": "Succeeded"
  },
  {
    "id": "/subscriptions/1234/resourceGroups/testrg/providers/Microsoft.KeyVault/vaults/xZbb",
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
      "bypass": "None",
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
        "id": "/subscriptions/1234/resourceGroups/testrg/providers/Microsoft.KeyVault/vaults/xZbb/privateEndpointConnections/sadeed",
        "properties": {
          "provisioningState": "Succeeded",
          "privateEndpoint": {
            "id": "/subscriptions/1234/resourceGroups/testrg/providers/Microsoft.Network/privateEndpoints/sadeed"
          },
          "privateLinkServiceConnectionState": {
            "status": "Approved",
            "actionsRequired": "None"
          }
        }
      }
    ],
    "accessPolicies": [
      {
        "tenantId": "2d4f0836-5935-47f5-954c-14e713119ac2",
        "objectId": "d198cb4d-de06-40ff-8fc4-4f643fbeabc5",
        "permissions": {
          "keys": [
            "Get",
            "List",
            "Update",
            "Create",
            "Import",
            "Delete",
            "Recover",
            "Backup",
            "Restore",
            "GetRotationPolicy",
            "SetRotationPolicy",
            "Rotate"
          ],
          "secrets": [
            "Get",
            "List",
            "Set",
            "Delete",
            "Recover",
            "Backup",
            "Restore"
          ],
          "certificates": [
            "Get",
            "List",
            "Update",
            "Create",
            "Import",
            "Delete",
            "Recover",
            "Backup",
            "Restore",
            "ManageContacts",
            "ManageIssuers",
            "GetIssuers",
            "ListIssuers",
            "SetIssuers",
            "DeleteIssuers"
          ]
        }
      }
    ],
    "enabledForDeployment": false,
    "enabledForDiskEncryption": false,
    "enabledForTemplateDeployment": false,
    "enableSoftDelete": true,
    "softDeleteRetentionInDays": 90,
    "enableRbacAuthorization": false,
    "vaultUri": "https://xzbb.vault.azure.net/",
    "provisioningState": "Succeeded"
  },
  {
    "id": "/subscriptions/1234/resourceGroups/testrg/providers/Microsoft.KeyVault/vaults/noNetworkAcls",
    "name": "noNetworkAcls",
    "type": "Microsoft.KeyVault/vaults",
    "location": "eastus",
    "tags": {},
    "sku": {
      "family": "A",
      "name": "Standard"
    },
    "tenantId": "2d4f0836-5935-47f5-954c-14e713119ac2",
    "privateEndpointConnections": [],
    "accessPolicies": [],
    "enabledForDeployment": false,
    "enabledForDiskEncryption": false,
    "enabledForTemplateDeployment": false,
    "enableSoftDelete": true,
    "softDeleteRetentionInDays": 90,
    "enableRbacAuthorization": false,
    "vaultUri": "https://nonetworkacls.vault.azure.net/",
    "provisioningState": "Succeeded"
  },
  {
    "id": "/subscriptions/1234/resourceGroups/testrg/providers/Microsoft.KeyVault/vaults/emptyDefaultAction",
    "name": "emptyDefaultAction",
    "type": "Microsoft.KeyVault/vaults",
    "location": "eastus",
    "tags": {},
    "sku": {
      "family": "A",
      "name": "Standard"
    },
    "tenantId": "2d4f0836-5935-47f5-954c-14e713119ac2",
    "networkAcls": {
      "bypass": "None",
      "ipRules": [],
      "virtualNetworkRules": []
    },
    "privateEndpointConnections": [],
    "accessPolicies": [],
    "enabledForDeployment": false,
    "enabledForDiskEncryption": false,
    "enabledForTemplateDeployment": false,
    "enableSoftDelete": true,
    "softDeleteRetentionInDays": 90,
    "enableRbacAuthorization": false,
    "vaultUri": "https://emptydefaultaction.vault.azure.net/",
    "provisioningState": "Succeeded"
  }
];

const createCache = (err, list, get) => {
  return {
    vaults: {
      list: {
        'eastus': {
          err: err,
          data: list
        }
      },
      getSecrets: {
        'eastus': get
      }
    }
  }
};

describe('restrictDefaultNetworkAccess', function () {
  describe('run', function () {
    it('should give passing result if no key vaults found', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include('No Key Vaults found');
        expect(results[0].region).to.equal('eastus');
        done()
      };

      auth.run(createCache(null, [], {}, {}), {}, callback);
    });

    it('should give unkown result if Unable to query for Key Vaults', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(3);
        expect(results[0].message).to.include('Unable to query for Key Vaults');
        expect(results[0].region).to.equal('eastus');
        done()
      };

      auth.run(createCache(null, null, {}, {}), {}, callback);
    });

    it('should give passing result if Key Vault does not allow access to all networks', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include('Key Vault does not allow access to all networks');
        expect(results[0].region).to.equal('eastus');
        done()
      };

      auth.run(createCache(null, [listVaults[0]]), {}, callback);
    });

    it('should give failing result if Key Vault allows access to all networks', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('Key Vault allows access to all networks');
        expect(results[0].region).to.equal('eastus');
        done()
      };

      auth.run(createCache(null, [listVaults[1]]), {}, callback);
    });

    it('should give failing result if Key Vault has no networkAcls configured', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('Key Vault allows access to all networks');
        expect(results[0].region).to.equal('eastus');
        done()
      };

      auth.run(createCache(null, [listVaults[2]]), {}, callback);
    });

    it('should give failing result if Key Vault has networkAcls but no defaultAction', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('Key Vault allows access to all networks');
        expect(results[0].region).to.equal('eastus');
        done()
      };

      auth.run(createCache(null, [listVaults[3]]), {}, callback);
    });
  })
});
