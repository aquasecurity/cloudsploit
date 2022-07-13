var expect = require('chai').expect;
var auth = require('./kvRecoveryEnabled');

const listVaults = [
    {
        id: '/subscriptions/123/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/test',
        name: 'test',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus',
        tags: { owner: 'kubernetes' },
        sku: { family: 'A', name: 'Standard' },
        tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
        accessPolicies: [
          {
            tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
            objectId: '123d1b11-52f8-4dfc-bf08-1b66fa2de1d5',
            permissions: [Object]
          },
          {
            tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
            objectId: 'b4062000-c33b-448b-817e-fa0f17bef4b9',
            permissions: [Object]
          },
          {
            tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
            objectId: '0ef24dfb-2712-44f2-98d2-2df7f946b338',
            permissions: [Object]
          }
        ],
        enabledForDeployment: true,
        enabledForDiskEncryption: true,
        enabledForTemplateDeployment: true,
        enableSoftDelete: true,
        enablePurgeProtection: true,
        softDeleteRetentionInDays: 7,
        enableRbacAuthorization: false,
        vaultUri: 'https://test.vault.azure.net/',
        provisioningState: 'Succeeded'
    },
    {
        id: '/subscriptions/123/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/test',
        name: 'test',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus',
        tags: { owner: 'kubernetes' },
        sku: { family: 'A', name: 'Standard' },
        tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
        accessPolicies: [
          {
            tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
            objectId: '123d1b11-52f8-4dfc-bf08-1b66fa2de1d5',
          },
        ],
        enabledForDeployment: true,
        enabledForDiskEncryption: true,
        enabledForTemplateDeployment: true,
        enableSoftDelete: false,
        softDeleteRetentionInDays: 7,
        enableRbacAuthorization: false,
        vaultUri: 'https://test.vault.azure.net/',
        provisioningState: 'Succeeded'
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

describe('kvRecoveryEnabled', function() {
    describe('run', function() {
        it('should give passing result if no key vaults found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [], {}), {}, callback);
        });

        it('should give unkown result if Unable to query for Key Vaults', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, null, {}), {}, callback);
        });

        it('should give passing result if Purge protection and soft delete are enabled for the Key Vault', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Purge protection and soft delete are enabled for the Key Vault');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]]), {}, callback);
        });

        it('should give failing result if Purge protection or soft delete is not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Purge protection');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[1]]), {}, callback);
        })
    })
});
