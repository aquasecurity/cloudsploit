var expect = require('chai').expect;
var auth = require('./keyVaultInUse');

const listKeyVaults = [
    {
        id: '/subscriptions/qdn32rdm-ebf6-437f-a3b0-28fc0d22111e/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/nauman-test',
        name: 'nauman-test',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus',
        tags: { owner: 'kubernetes' },
        sku: { family: 'A', name: 'Standard' },
        tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
        accessPolicies: [
            {
                tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
                objectId: 'b4062000-c33b-448b-817e-fa0f17bef4b9',
                permissions: {
                    keys: ['Get', 'List'],
                    secrets: ['Get', 'List'],
                    certificates: ['Get', 'List']
                }
            }
        ],
        enableSoftDelete: true,
        softDeleteRetentionInDays: 7,
        enableRbacAuthorization: false,
        vaultUri: 'https://nauman-test.vault.azure.net/',
        provisioningState: 'Succeeded'
    }
];

const getKeys = [
    {
        "attributes": {
          "created": "2022-04-10T17:57:43+00:00",
          "enabled": true,
          "expires": null,
          "notBefore": null,
          "recoveryLevel": "CustomizedRecoverable+Purgeable",
          "updated": "2022-04-10T17:57:43+00:00"
        },
        "kid": "https://nauman-test.vault.azure.net/keys/nauman-test",
        "managed": null,
        "name": "nauman-test",
        "tags": {
          "hello": "world"
        }
    }
];

const createCache = (err, list, keys) => {
    return {
        vaults: {
            list: {
                'eastus': {
                    err: err,
                    data: list
                }
            },
            getKeys: {
                'eastus': {
                    '/subscriptions/qdn32rdm-ebf6-437f-a3b0-28fc0d22111e/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/nauman-test': {
                        err: err,
                        data: keys
                    }
                }
            }
        }
    }
};

describe('keyVaultInUse', function() {
    describe('run', function() {
        it('should give failing result if no key vaults found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vaults are not being used to store secrets');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [], {}), {}, callback);
        });

        it('should give passing result if key vaults are being used to store secrets', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key Vaults are being used to store secrets');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], [getKeys[0]]), {}, callback);
        });

        it('should give failing result if no keys in key vaults found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vaults are not being used to store secrets');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [], {}), {}, callback);
        });
    });
});