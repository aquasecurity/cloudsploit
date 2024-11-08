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
        id: '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-vault',
        name: 'test-vault',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus',
        properties: {
            enableRbacAuthorization: true,
            vaultUri: 'https://test-vault.vault.azure.net/'
        }
    },
    {
        id: '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-vault-2',
        name: 'test-vault-2',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus',
        properties: {
            enableRbacAuthorization: false,
            vaultUri: 'https://test-vault-2.vault.azure.net/'
        }
    }
];

const getKeys = [
    {
        "attributes": {
          "created": "2022-04-10T17:57:43+00:00",
          "enabled": true,
          "expires": null,
          "notBefore": null,
          "updated": "2022-04-10T17:57:43+00:00"
        },
        "kid": "https://test-vault.vault.azure.net/keys/test-key",
        "name": "test-key"
    },
    {
        "attributes": {
          "created": "2022-04-10T17:57:43+00:00",
          "enabled": true,
          "expires": keyExpiryPass,
          "notBefore": null,
          "updated": "2022-04-10T17:57:43+00:00"
        },
        "kid": "https://test-vault.vault.azure.net/keys/test-key-2",
        "name": "test-key-2"
    },
    {
        "attributes": {
          "created": "2022-04-10T17:57:43+00:00",
          "enabled": true,
          "expires": keyExpiryFail,
          "notBefore": null,
          "updated": "2022-04-10T17:57:43+00:00"
        },
        "kid": "https://test-vault.vault.azure.net/keys/test-key-3",
        "name": "test-key-3"
    },
    {
        "attributes": {
          "created": "2022-04-10T17:57:43+00:00",
          "enabled": true,
          "expires": keyExpired,
          "notBefore": null,
          "updated": "2022-04-10T17:57:43+00:00"
        },
        "kid": "https://test-vault.vault.azure.net/keys/test-key-4",
        "name": "test-key-4"
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
                    '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-vault': {
                        err: err,
                        data: keys
                    }
                }
            }
        }
    }
};

describe('keyVaultKeyExpiryRbac', function() {
    describe('run', function() {
        it('should give passing result if no key vaults found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vault keys found in RBAC vault');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [], {}), {}, callback);
        });

        it('should give passing result if expiration is not set on keys', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key expiration is not enabled in RBAC vault');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], [getKeys[0]]), {}, callback);
        });

        it('should give passing result if expiry date is not yet reached', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key in RBAC vault expires in');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], [getKeys[1]]), { key_vault_key_expiry_fail: '30' }, callback);
        });

        it('should give failing result if the key has expired', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key in RBAC vault expired');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], [getKeys[3]]), { key_vault_key_expiry_fail: '40' }, callback);
        });

        it('should give failing result if the key expires within failure expiry date', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key in RBAC vault expires');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], [getKeys[2]]), { key_vault_key_expiry_fail: '40' }, callback);
        });
    });
}); 
