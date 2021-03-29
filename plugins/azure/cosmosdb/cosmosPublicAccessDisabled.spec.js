var expect = require('chai').expect;
var cosmosPublicAccessDisabled = require('./cosmosPublicAccessDisabled');

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
        "enableAutomaticFailover": true,
        "enableMultipleWriteLocations": false,
        "enablePartitionKeyMonitor": false,
        "isVirtualNetworkFilterEnabled": true,
        "virtualNetworkRules": [
            {
                "id": '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/deleteasap/providers/Microsoft.Network/virtualNetworks/deleteasap-vnet/subnets/default',
                "ignoreMissingVNetServiceEndpoint": false
            }
        ],
        "EnabledApiTypes": "Sql",
        "disableKeyBasedMetadataWriteAccess": false,
        "enableAnalyticalStorage": false,
        "instanceId": "5f3e6edc-33c6-4a47-81aa-108af12d4fba",
        "createMode": "Default",
        "databaseAccountOfferType": "Standard",
        "ipRules": [
            { "ipAddressOrRange": '104.42.195.92' },
            { "ipAddressOrRange": '40.76.54.131' }
        ]
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

describe('cosmosPublicAccessDisabled', function() {
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

            cosmosPublicAccessDisabled.run(cache, {}, callback);
        });

        it('should give passing result if Cosmos DB account denies public access', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cosmos DB account denies public access');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[0]]
            );

            cosmosPublicAccessDisabled.run(cache, {}, callback);
        });

        it('should give failing result if Cosmos DB account allows public access', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cosmos DB account allows public access');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[1]],
            );

            cosmosPublicAccessDisabled.run(cache, {}, callback);
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

            cosmosPublicAccessDisabled.run(cache, {}, callback);
        });
    })
});
