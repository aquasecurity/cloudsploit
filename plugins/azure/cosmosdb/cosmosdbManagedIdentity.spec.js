var expect = require('chai').expect;
var cosmosdbManagedIdentity = require('./cosmosdbManagedIdentity');

const databaseAccounts = [
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos",
        "name": "aqua-cosmos",
        "location": "East US",
        "tags": {"key": "value"},
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "provisioningState": "Succeeded",
        "identity": {
            "principalId":"e8c02afc-8fb0-43eb-985f-5bb60a87e7aa",
            "type":"systemassigned"
        },
        "documentEndpoint": "https://aqua-cosmos.documents.azure.com:443/",
        "publicNetworkAccess": "Enabled",
        "enableAutomaticFailover": true,
        "enableMultipleWriteLocations": false,
        "enablePartitionKeyMonitor": false,
        "isVirtualNetworkFilterEnabled": true,
        "EnabledApiTypes": "Sql",
        "disableKeyBasedMetadataWriteAccess": false,
        "enableAnalyticalStorage": false,
        "instanceId": "5f3e6edc-33c6-4a47-81aa-108af12d4fba",
        "createMode": "Default",
        "databaseAccountOfferType": "Standard",
    },
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos",
        "name": "aqua-cosmos",
        "location": "East US",
        "tags": {},
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "provisioningState": "Succeeded",
        "documentEndpoint": "https://aqua-cosmos.documents.azure.com:443/",
        "publicNetworkAccess": "Enabled",
        "identity": {
            "type":"None"
        },
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

const createCache = (accounts, accountsErr) => {
    return {
        databaseAccounts: {
            list: {
                'eastus': {
                    err: accountsErr,
                    data: accounts
                }
            }
        }
    }
};

describe('cosmosdbManagedIdentity', function() {
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

            cosmosdbManagedIdentity.run(cache, {}, callback);
        });

        it('should give passing result if Cosmos db has managed identity', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cosmos DB account has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[0]]
            );

            cosmosdbManagedIdentity.run(cache, {}, callback);
        });

        it('should give failing result if Azure Cosmos db does not have managed identity', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cosmos DB account does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[1]],
            );

            cosmosdbManagedIdentity.run(cache, {}, callback);
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

            cosmosdbManagedIdentity.run(cache, {}, callback);
        });
    })
});
