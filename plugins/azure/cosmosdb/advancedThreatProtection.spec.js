var expect = require('chai').expect;
var advancedThreatProtection = require('./advancedThreatProtection');

const databaseAccounts = [
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos",
        "name": "aqua-cosmos",
        "location": "East US",
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "provisioningState": "Succeeded",
        "documentEndpoint": "https://aqua-cosmos.documents.azure.com:443/",
        "publicNetworkAccess": "Enabled",
        "enableAutomaticFailover": false,
        "enableMultipleWriteLocations": false,
        "enablePartitionKeyMonitor": false,
        "isVirtualNetworkFilterEnabled": false,
        "virtualNetworkRules": [],
        "EnabledApiTypes": "Sql",
        "disableKeyBasedMetadataWriteAccess": false,
        "enableAnalyticalStorage": false,
        "instanceId": "5f3e6edc-33c6-4a47-81aa-108af12d4fba",
        "createMode": "Default",
        "databaseAccountOfferType": "Standard"
    },
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos",
        "name": "aqua-cosmos",
        "location": "East US",
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "provisioningState": "Succeeded",
        "documentEndpoint": "https://aqua-cosmos.documents.azure.com:443/",
        "publicNetworkAccess": "Enabled",
        "enableAutomaticFailover": false,
        "enableMultipleWriteLocations": false,
        "enablePartitionKeyMonitor": false,
        "isVirtualNetworkFilterEnabled": false,
        "virtualNetworkRules": [],
        "EnabledApiTypes": "Cassandra",
        "disableKeyBasedMetadataWriteAccess": false,
        "enableAnalyticalStorage": false,
        "instanceId": "5f3e6edc-33c6-4a47-81aa-108af12d4fba",
        "createMode": "Default",
        "databaseAccountOfferType": "Standard"
    }
];

const atpGet = [
    {
        id: 'subscriptions/123/resourceGroups/test-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos/providers/Microsoft.Security/advancedThreatProtectionSettings/current',
        type: 'Microsoft.Security/advancedThreatProtectionSettings',
        name: 'current',
        isEnabled: true
    },
    {
        id: 'subscriptions/123/resourceGroups/test-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos/providers/Microsoft.Security/advancedThreatProtectionSettings/current',
        type: 'Microsoft.Security/advancedThreatProtectionSettings',
        name: 'current',
        isEnabled: false
    }
];

const createCache = (accounts, accountsErr, atpGet, atpErr) => {
    const id = (accounts && accounts.length) ? accounts[0].id : null;
    return {
        databaseAccounts: {
            list: {
                'eastus': {
                    err: accountsErr,
                    data: accounts
                }
            }
        },
        advancedThreatProtection: {
            get: {
                'eastus': {
                    [id]: {
                        err: atpErr,
                        data: atpGet
                    }
                }
            }
        }
    }
};

describe('advancedThreatProtection', function() {
    describe('run', function() {
        it('should give passing result if no Cosmos DB accounts found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Cosmos DB accounts found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            advancedThreatProtection.run(cache, {}, callback);
        });

        it('should give passing result if Advanced threat protection feature is not supported for current resource', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Advanced threat protection feature is not supported');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[1]]
            );

            advancedThreatProtection.run(cache, {}, callback);
        });

        it('should give failing result if Advanced threat protection is not enabled for Cosmos DB account', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Advanced threat protection is not enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[0]],
                null,
                atpGet[1]
            );

            advancedThreatProtection.run(cache, {}, callback);
        });

        it('should give passing result if Advanced threat protection is enabled for Cosmos DB account', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Advanced threat protection is enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[0]],
                null,
                atpGet[0]
            );

            advancedThreatProtection.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for Cosmos DB accounts', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Cosmos DB accounts');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [],
                { message: 'Unable to query Cosmos DB accounts'}
            );

            advancedThreatProtection.run(cache, {}, callback);
        });
    })
})