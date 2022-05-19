var expect = require('chai').expect;
var auth = require('./keyVaultKeyExpiry');

var keyExpiryPass = new Date();
keyExpiryPass.setMonth(keyExpiryPass.getMonth() + 2);

var keyExpiryFail = new Date();
keyExpiryFail.setMonth(keyExpiryFail.getMonth() + 1);

var keyExpired = new Date();
keyExpired.setMonth(keyExpired.getMonth() - 1);

const listKeyVaults = [
    {
        id: '/subscriptions/abcdfget-ebf6-437f-a3b0-28fc0d22111e/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/nauman-test',
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
    },
    {
        "attributes": {
          "created": "2022-04-10T17:57:43+00:00",
          "enabled": true,
          "expires": keyExpiryPass,
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
    },
    {
        "attributes": {
          "created": "2022-04-10T17:57:43+00:00",
          "enabled": true,
          "expires": keyExpiryFail,
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
    },
    {
        "attributes": {
          "created": "2022-04-10T17:57:43+00:00",
          "enabled": true,
          "expires": keyExpired,
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
                    '/subscriptions/abcdfget-ebf6-437f-a3b0-28fc0d22111e/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/nauman-test': {
                        err: err,
                        data: keys
                    }
                }
            }
        }
    }
};

describe('keyVaultKeyExpiry', function() {
    describe('run', function() {
        it('should give passing result if no keys found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [], {}), {}, callback);
        });

        it('should give passing result if expiration is not set on keys', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key expiration is not enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], [getKeys[0]]), {}, callback);
        });

        it('should give passing result if expiry date is not yet reached', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key expires in');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, listKeyVaults, [getKeys[1]]), { key_vault_key_expiry_fail: '30' }, callback);
        });

        it('should give failing results if the key has reached', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key expired');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, listKeyVaults, [getKeys[3]]), { key_vault_key_expiry_fail: '40' }, callback);
        });

        it('should give failing results if the key expired within failure expiry date', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key expires');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, listKeyVaults, [getKeys[2]]), { key_vault_key_expiry_fail: '40' }, callback);
        });
    });
});
