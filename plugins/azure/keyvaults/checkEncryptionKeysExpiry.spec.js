var expect = require('chai').expect;
var auth = require('./checkEncryptionKeysExpiry');

const listKeyVaults = [
    {
        id: '/subscriptions/dce7d7as-ebf6-437f-a3b0-28fc0d22111e/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/nauman-test',
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
          "expires": "2022-08-31T17:52:06+00:00",
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
          "expires": "2022-04-01T17:52:06+00:00",
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
                    '/subscriptions/dce7d7as-ebf6-437f-a3b0-28fc0d22111e/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/nauman-test': {
                        err: err,
                        data: keys
                    }
                }
            }
        }
    }
};

describe('checkEncryptionKeysExpiry', function() {
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

        it('should give failing result if expiration is not set on keys', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
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
                expect(results[0].message).to.include('Key expiry date is not yet reached');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, listKeyVaults, [getKeys[1]]), {}, callback);
        });

        it('should give failing results if the key has reached its expiry date', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key has reached its expiry date');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, listKeyVaults, [getKeys[2]]), {}, callback);
        });
    });
});
