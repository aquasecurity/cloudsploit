var expect = require('chai').expect;
var auth = require('./keyVaultSecretExpiry');

var secretExpiryPass = new Date();
secretExpiryPass.setMonth(secretExpiryPass.getMonth() + 2);

var secretExpiryFail = new Date();
secretExpiryFail.setMonth(secretExpiryFail.getMonth() + 1);

var secretExpired = new Date();
secretExpired.setMonth(secretExpired.getMonth() - 1);

const listKeyVaults = [
    {
        "id": "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault",
        "name": "testvault",
        "type": "Microsoft.KeyVault/vaults",
        "location": "eastus",
        "tags": {},
        "sku": {
            "family": "A",
            "name": "Standard"
        },
        "properties": {
            "enableRbacAuthorization": true
        }
    },
    {
        "id": "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault",
        "name": "testvault",
        "type": "Microsoft.KeyVault/vaults",
        "location": "eastus",
        "tags": {},
        "sku": {
            "family": "A",
            "name": "Standard"
        },
        "properties": {
            "enableRbacAuthorization": false
        }
    }
];

const getSecrets = [
    {
        '/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault': {
            data: [
                {
                    "id": "https://testvault.vault.azure.net/secrets/mysecret",
                    "attributes": {
                        "enabled": true,
                        "expiry": null,
                        "created": 1572289869,
                        "updated": 1572290380,
                        "recoveryLevel": "Recoverable+Purgeable"
                    },
                    "tags": {}
                }
            ]
        }
    },{
        '/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault': {
            data: [
                {
                    "id": "https://testvault.vault.azure.net/secrets/mysecret",
                    "attributes": {
                        "enabled": true,
                        "expiry": secretExpiryPass,
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
                        "expiry": secretExpiryFail,
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
                        "expiry": secretExpired,
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
                        "expiry": secretExpired,
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

const createCache = (err, list, get) => {
    return {
        vaults: {
            list: {
                'eastus': {
                    err: err,
                    data: list
                }
            },
            getSecrets: {
                'eastus': get
            }
        }
    }
};

describe('keyVaultSecretExpiry', function() {
    describe('run', function() {
        it('should give passing result if no secrets found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [], {}), {}, callback);
        });

        it('should give passing result if vault is not RBAC-enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key Vault is not RBAC-enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[1]], {}), {}, callback);
        });

        it('should give passing result if secret expiration is not enabled in RBAC vault', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Secret expiration is not enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], getSecrets[0]), {}, callback);
        });

        it('should give passing result if secret expiry is not yet reached in RBAC vault', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Secret expires');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], getSecrets[1]), {}, callback);
        });

        it('should give failing result if secret has expired', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Secret expired');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], getSecrets[3]), {}, callback);
        });

        it('should give failing result if secret expires within failure expiry date', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Secret expires');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], getSecrets[2]), { key_vault_secret_expiry_fail: '40' }, callback);
        });

        it('should give passing result if key is disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Secret is not enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listKeyVaults[0]], getSecrets[4]), {}, callback);
        });
    })
});
