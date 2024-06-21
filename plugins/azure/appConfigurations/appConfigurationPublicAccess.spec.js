var expect = require('chai').expect;
var appConfigurationPublicAccess = require('./appConfigurationPublicAccess.js');

const appConfigurations = [
    {
        "type": "Microsoft.AppConfiguration/configurationStores",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "creationDate": "2023-12-27T09:26:54+00:00",
        "endpoint": "https://dummy-test-rg.azconfig.io",
        "encryption": {
        "keyVaultProperties": null
        },
        "privateEndpointConnections": null,
        "publicNetworkAccess": "Enabled",
        "disableLocalAuth": false,
        "softDeleteRetentionInDays": 0,
        "enablePurgeProtection": false,
        "id": "/subscriptions/123/resourceGroups/dummy-rg/providers/Microsoft.AppConfiguration/configurationStores/dummy-test-rg",
        "name": "dummy-test-rg",
        "tags": {}
    },
    {
        "type": "Microsoft.AppConfiguration/configurationStores",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "creationDate": "2023-12-27T09:26:54+00:00",
        "endpoint": "https://dummy-test-rg.azconfig.io",
        "encryption": {
        "keyVaultProperties": null
        },
        "privateEndpointConnections": null,
        "publicNetworkAccess": "Disabled",
        "disableLocalAuth": false,
        "softDeleteRetentionInDays": 0,
        "enablePurgeProtection": false,
        "id": "/subscriptions/123/resourceGroups/dummy-rg/providers/Microsoft.AppConfiguration/configurationStores/dummy-test-rg",
        "name": "dummy-test-rg",
        "tags": {},
        "identity": {
            "type": "systemassigned,userassigned",
            "principalId": "1234",
            "tenantId": "1234",
            "userAssignedIdentities": {
              "/subscriptions/123/resourcegroups/dummy-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/testdummy": {
                "PrincipalId": "12344",
                "ClientId": "123445"
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

describe('appConfigurationPublicAccess', function () {
    describe('run', function () {

        it('should give pass result if No existing app configurations found', function (done) {
            const cache = createCache([]);
            appConfigurationPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Configurations found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query app configurations:', function (done) {
            const cache = createCache(null, 'Error');
            appConfigurationPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Configuration:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if App Configuration has public network access disabled', function (done) {
            const cache = createCache([appConfigurations[1]]);
            appConfigurationPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Configuration has public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if App Configuration does not have public network access disabled', function (done) {
            const cache = createCache([appConfigurations[0]]);
            appConfigurationPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Configuration does not have public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});