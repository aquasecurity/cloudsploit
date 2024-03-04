var expect = require('chai').expect;
var privateEndpoint = require('./keyVaultsPrivateEndpoint');

const listVaults = [
    {
        id: '/subscriptions/123/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/test',
        name: 'test',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus',
    },
    {
        id: '/subscriptions/123/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/test',
        name: 'test',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus',
        tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
        privateEndpointConnections: [
            {
                id: '/subscriptions/123/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/test',
                properties: [Object]
            }
        ],
        accessPolicies: [
          {
            tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
            objectId: '123d1b11-52f8-4dfc-bf08-1b66fa2de1d5',
          },
        ],
    }
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

describe('keyVaultsPrivateEndpoint', function() {
    describe('run', function() {
        it('should give passing result if no key vaults found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            privateEndpoint.run(createCache(null, [], {}), {}, callback);
        });

        it('should give unkown result if Unable to query for Key Vaults', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            privateEndpoint.run(createCache(null, null, {}), {}, callback);
        });

        it('should give passing result if private endpoints are configured for the Key Vault', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key Vault has private endpoints configured');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            privateEndpoint.run(createCache(null, [listVaults[1]]), {}, callback);
        });

        it('should give failing result if private endpoints are not configured for key vault', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vault does not have private endpoints configured');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            privateEndpoint.run(createCache(null, [listVaults[0]]), {}, callback);
        })
    })
});
