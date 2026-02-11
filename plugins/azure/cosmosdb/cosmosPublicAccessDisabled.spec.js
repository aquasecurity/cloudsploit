var expect = require('chai').expect;
var cosmosPublicAccessDisabled = require('./cosmosPublicAccessDisabled');

const databaseAccounts = [
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos-disabled",
        "name": "aqua-cosmos-disabled",
        "location": "East US",
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "publicNetworkAccess": "Disabled",
        "isVirtualNetworkFilterEnabled": false
    },
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos-selected-networks",
        "name": "aqua-cosmos-selected-networks",
        "location": "East US",
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "publicNetworkAccess": "Enabled",
        "isVirtualNetworkFilterEnabled": true,
        "ipRules": [
            { "ipAddressOrRange": '104.42.195.92' },
            { "ipAddressOrRange": '40.76.54.131' }
        ]
    },
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos-all-networks",
        "name": "aqua-cosmos-all-networks",
        "location": "East US",
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "publicNetworkAccess": "Enabled",
        "isVirtualNetworkFilterEnabled": false,
        "virtualNetworkRules": []
    },
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos-open-ipv4",
        "name": "aqua-cosmos-open-ipv4",
        "location": "East US",
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "publicNetworkAccess": "Enabled",
        "isVirtualNetworkFilterEnabled": true,
        "ipRules": [
            { "ipAddressOrRange": '104.42.195.92' },
            { "ipAddressOrRange": '0.0.0.0/0' }
        ]
    },
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos-open-ipv6",
        "name": "aqua-cosmos-open-ipv6",
        "location": "East US",
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "publicNetworkAccess": "Enabled",
        "isVirtualNetworkFilterEnabled": true,
        "ipRules": [
            { "ipAddressOrRange": '::/0' }
        ]
    },
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos-selected-no-rules",
        "name": "aqua-cosmos-selected-no-rules",
        "location": "East US",
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "publicNetworkAccess": "Enabled",
        "isVirtualNetworkFilterEnabled": true,
        "ipRules": []
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

        it('should give passing result if public network access is disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cosmos DB account has public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[0]]
            );

            cosmosPublicAccessDisabled.run(cache, {}, callback);
        });

        it('should give passing result if selected networks with specific IPs', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cosmos DB account denies public access');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[1]]
            );

            cosmosPublicAccessDisabled.run(cache, {}, callback);
        });

        it('should give failing result if public network enabled with no restrictions', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('allows public access');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[2]]
            );

            cosmosPublicAccessDisabled.run(cache, {}, callback);
        });

        it('should give failing result if IP rules contain 0.0.0.0/0', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cosmos DB account allows unrestricted public access');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[3]]
            );

            cosmosPublicAccessDisabled.run(cache, {}, callback);
        });

        it('should give failing result if IP rules contain ::/0', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cosmos DB account allows unrestricted public access');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[4]]
            );

            cosmosPublicAccessDisabled.run(cache, {}, callback);
        });

        it('should give passing result if selected networks with no ip or vnet rules (effectively deny-all)', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cosmos DB account denies public access');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[5]]
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
