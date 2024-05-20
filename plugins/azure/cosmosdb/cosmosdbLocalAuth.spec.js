var expect = require('chai').expect;
var cosmosdbLocalAuth = require('./cosmosdbLocalAuth');

const databaseAccounts = [
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos",
        "name": "aqua-cosmos",
        "location": "East US",
        "tags": {"key": "value"},
        "disableLocalAuth": true,
    },
    {
        "id": "/subscriptions/123/resourceGroups/tets-rg/providers/Microsoft.DocumentDB/databaseAccounts/aqua-cosmos",
        "name": "aqua-cosmos",
        "location": "East US",
        "tags": {},
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "kind": "GlobalDocumentDB",
        "disableLocalAuth": false
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

describe('cosmosdbLocalAuth', function() {
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

            cosmosdbLocalAuth.run(cache, {}, callback);
        });

        it('should give passing result if Cosmos DB has local auth disbaled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cosmos DB account has local authentication disabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[0]]
            );

            cosmosdbLocalAuth.run(cache, {}, callback);
        });

        it('should give failing result if Cosmos DB has local auth enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cosmos DB account has local authentication enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [databaseAccounts[1]],
            );

            cosmosdbLocalAuth.run(cache, {}, callback);
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

            cosmosdbLocalAuth.run(cache, {}, callback);
        });
    })
});
