var expect = require('chai').expect;
var appConfigManagedIdentity = require('./appConfigManagedIdentity.js');

const appConfigurations = [
    {
        "type": "Microsoft.AppConfiguration/configurationStores",
        "location": "eastus",
        "properties": {
          "provisioningState": "Succeeded",
          "creationDate": "2023-12-27T09:26:54+00:00",
          "endpoint": "https://meerab-test-rg.azconfig.io",
          "encryption": {
            "keyVaultProperties": null
          },
          "privateEndpointConnections": null,
          "publicNetworkAccess": "Disabled",
          "disableLocalAuth": false,
          "softDeleteRetentionInDays": 0,
          "enablePurgeProtection": false
        },
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourceGroups/meerab-rg/providers/Microsoft.AppConfiguration/configurationStores/meerab-test-rg",
        "name": "meerab-test-rg",
        "tags": {}
    },
    {
        "type": "Microsoft.AppConfiguration/configurationStores",
        "location": "eastus",
        "properties": {
          "provisioningState": "Succeeded",
          "creationDate": "2023-12-27T09:26:54+00:00",
          "endpoint": "https://meerab-test-rg.azconfig.io",
          "encryption": {
            "keyVaultProperties": null
          },
          "privateEndpointConnections": null,
          "publicNetworkAccess": "Disabled",
          "disableLocalAuth": false,
          "softDeleteRetentionInDays": 0,
          "enablePurgeProtection": false
        },
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourceGroups/meerab-rg/providers/Microsoft.AppConfiguration/configurationStores/meerab-test-rg",
        "name": "meerab-test-rg",
        "tags": {},
        "identity": {
            "type": "systemassigned,userassigned",
            "principalId": "dc03d47d-e6df-491f-aebe-50a93412a890",
            "tenantId": "d207c7bd-fcb1-4dd3-855a-cfd2f9b651e8",
            "userAssignedIdentities": {
              "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/testmeerab": {
                "PrincipalId": "1d34c2cd-bd53-487d-b3a9-6064465497c9",
                "ClientId": "2071caa1-3668-4de3-babc-155cfe3e38e5"
              }
            }
        }
    }
];

const createCache = (appConfigurations,err) => {
    return {
        appConfigurations: {
            list: {
                'eastus': {
                    data: appConfigurations,
                    err: err
                }
            }
        }
    }
};

describe('appConfigManagedIdentity', function () {
    describe('run', function () {

        it('should give pass result if No existing app configurations found', function (done) {
            const cache = createCache([]);
            appConfigManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Configurations found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query app configurations:', function (done) {
            const cache = createCache(null, 'Error');
            appConfigManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Configuration:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if App Configuration has managed identity enabled', function (done) {
            const cache = createCache([appConfigurations[1]]);
            appConfigManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Configuration has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if App Configuration does not have managed identity enabled', function (done) {
            const cache = createCache([appConfigurations[0]]);
            appConfigManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Configuration does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});