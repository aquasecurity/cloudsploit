var expect = require('chai').expect;
var auth = require('./cmkCreationForAppTier');

const listVaults = [
    {
        "id": "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault",
        "name": "testvault",
        "type": "Microsoft.KeyVault/vaults",
        "location": "eastus",
        "tags": {},
        "sku": {
            "family": "A",
            "name": "Standard"
        }
    },
    {
        "id": "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault",
        "name": "testvault",
        "type": "Microsoft.KeyVault/vaults",
        "location": "eastus",
        "tags": { hello: 'world' },
        "sku": {
            "family": "A",
            "name": "Standard"
        }
    }
];

const getKeys = [
    {
        '/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault': {
            data: [
                {
                    "id": "https://testvault.vault.azure.net/secrets/mysecret",
                    "attributes": {
                        "enabled": true,
                        "exp": null,
                        "created": 1572289869,
                        "updated": 1572290380,
                        "recoveryLevel": "Recoverable+Purgeable"
                    },
                    "tags": {}
                }
            ]
        }
    },
    {
        '/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault': {
            data: [
                {
                    "id": "https://testvault.vault.azure.net/secrets/mysecret",
                    "attributes": {
                        "enabled": true,
                        "exp": 1635448252,
                        "created": 1572289869,
                        "updated": 1572290380,
                        "recoveryLevel": "Recoverable+Purgeable"
                    },
                    "tags": {}
                }
            ]
        }
    },
    {
        '/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault': {
            data: [
                {
                    "id": "https://testvault.vault.azure.net/secrets/mysecret",
                    "attributes": {
                        "enabled": false,
                        "exp": 1635448252,
                        "created": 1572289869,
                        "updated": 1572290380,
                        "recoveryLevel": "Recoverable+Purgeable"
                    },
                    "tags": {}
                }
            ]
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
                'eastus': keys
            }
        }
    }
};

describe('cmkCreationForAppTier', function() {
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

        it('should give passing result if expiration is set on keys', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Expiry date is set for the secret');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[1]], getKeys[1]), {}, callback);
        });

        it('should give passing result if key is disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The secret is disabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[2]], getKeys[2]), {}, callback);
        })
    })
});
