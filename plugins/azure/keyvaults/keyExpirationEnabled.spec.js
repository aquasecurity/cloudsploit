var expect = require('chai').expect;
var auth = require('./keyExpirationEnabled');

const listVaults = [
    {
        "id": "/subscriptions/123/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault",
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
        "id": "/subscriptions/123/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault",
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
        "kid": "https://testvault.vault.azure.net/keys/test",
        "attributes": {
            "enabled": true,
            "exp": null,
            "created": 1572289869,
            "updated": 1572290380,
            "recoveryLevel": "Recoverable+Purgeable"
        },
        "tags": {
            "apptier": "app-rier"
        }
    },
    {
        "kid": "https://testvault.vault.azure.net/keys/test",
        "attributes": {
            "enabled": true,
            "exp": 1635448252,
            "created": 1572289869,
            "updated": 1572290380,
            "recoveryLevel": "Recoverable+Purgeable"
        },
        "tags": {}
    },
    {
        "kid": "https://testvault.vault.azure.net/keys/test",
        "tags": {}
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
                    '/subscriptions/123/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault': {
                        data: keys
                    }
                }
            }
        }
    }
};

describe('keyExpirationEnabled', function() {
    describe('run', function() {
        it('should give Passing result if no key vaults found', function(done) {
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

        it('should give unkown result if Unable to query for Key Vaults keys', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vault keys');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], null), {}, callback);
        });

        it('should give passing result if Expiry date is set for the key', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Expiry date is set for the key');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[1]], [getKeys[1]]), {}, callback);
        });

        it('should give failing result if Expiry date is not set for the key', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Expiry date is not set for the key');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[1]], [getKeys[0]]), {}, callback);
        });

        
        it('should give failing result if Expiry date is not set for the key', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Expiry date is not set for the key');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[1]], [getKeys[2]]), {}, callback);
        })
    })
});
