var expect = require('chai').expect;
var storageAccountsTlsVersion = require('./storageAccountsTlsVersion');

const storageAccounts = [
    {
        "sku": {
          "name": "Standard_LRS",
          "tier": "Standard"
        },
        "kind": "StorageV2",
        "id": "/subscriptions/dce7d0ad-jdde-e23c-2edc-28fc0d22117e/resourceGroups/cloud-shell-storage-centralindia/providers/Microsoft.Storage/storageAccounts/testsa",
        "name": "csg10032001681f5f9e",
        "type": "Microsoft.Storage/storageAccounts",
        "location": "centralindia",
        "tags": {
          "ms-resource-usage": "azure-cloud-shell"
        },
        "privateEndpointConnections": [],
        "minimumTlsVersion": "TLS1_2",
        "allowBlobPublicAccess": false,
        "networkAcls": {
          "bypass": "AzureServices",
          "virtualNetworkRules": [],
          "ipRules": [],
          "defaultAction": "Allow"
        },
        "supportsHttpsTrafficOnly": true,
        "encryption": {
          "services": {
            "file": {
              "keyType": "Account",
              "enabled": true,
              "lastEnabledTime": "2021-08-05T14:20:46.8158854Z"
            },
            "blob": {
              "keyType": "Account",
              "enabled": true,
              "lastEnabledTime": "2021-08-05T14:20:46.8158854Z"
            }
          },
          "keySource": "Microsoft.Storage"
        },
        "accessTier": "Hot",
        "provisioningState": "Succeeded",
        "creationTime": "2021-08-05T14:20:46.7377764Z",
        "primaryLocation": "centralindia",
        "statusOfPrimary": "available"
    },
    {
        "sku": {
          "name": "Standard_LRS",
          "tier": "Standard"
        },
        "kind": "StorageV2",
        "id": "/subscriptions/dce7d0ad-jdde-e23c-2edc-28fc0d22117e/resourceGroups/cloud-shell-storage-centralindia/providers/Microsoft.Storage/storageAccounts/testsa",
        "name": "csg10032001681f5f9e",
        "type": "Microsoft.Storage/storageAccounts",
        "location": "centralindia",
        "tags": {
          "ms-resource-usage": "azure-cloud-shell"
        },
        "privateEndpointConnections": [],
        "minimumTlsVersion": "TLS1_1",
        "allowBlobPublicAccess": false,
        "networkAcls": {
          "bypass": "AzureServices",
          "virtualNetworkRules": [],
          "ipRules": [],
          "defaultAction": "Allow"
        },
        "supportsHttpsTrafficOnly": true,
        "encryption": {
          "services": {
            "file": {
              "keyType": "Account",
              "enabled": true,
              "lastEnabledTime": "2021-08-05T14:20:46.8158854Z"
            },
            "blob": {
              "keyType": "Account",
              "enabled": true,
              "lastEnabledTime": "2021-08-05T14:20:46.8158854Z"
            }
          },
          "keySource": "Microsoft.Storage"
        },
        "accessTier": "Hot",
        "provisioningState": "Succeeded",
        "creationTime": "2021-08-05T14:20:46.7377764Z",
        "primaryLocation": "centralindia",
        "statusOfPrimary": "available"
    }
];


const createCache = (accounts, accountsErr) => {
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    err: accountsErr,
                    data: accounts
                }
            }
        }
    }
};

describe('storageAccountsTlsVersion', function() {
    describe('run', function() {
        it('should give passing result if no Storage Accounts found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Storage Accounts found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            storageAccountsTlsVersion.run(cache, {}, callback);
        });

        it('should give failing result if Storage Account is using TLS version less than desired TLS version', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('less than desired TLS version');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [storageAccounts[1]],
            );

            storageAccountsTlsVersion.run(cache, { sa_min_tls_version: '1.2' }, callback);
        });

        it('should give passing result if Storage Account is using TLS version equal to or higher than desired TLS version', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('equal to or higher than desired TLS version');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [storageAccounts[0]]
            );

            storageAccountsTlsVersion.run(cache, { sa_min_tls_version: '1.2' }, callback);
        });

        it('should give unknown result if unable to query for Storage Accounts', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                storageAccounts,
                { message: 'unable to query servers'}
            );

            storageAccountsTlsVersion.run(cache, {}, callback);
        });
    })
})