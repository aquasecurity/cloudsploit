var expect = require('chai').expect;
var recoveryVaultByokEncrypted = require('./recoveryVaultByokEncrypted');

const listServiceVaults = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/77777777-b0c6-47a2-b37c-d8e65a629c18/resourceGroups/HelloWorld/providers/Microsoft.RecoveryServices/vaults/today1',
        'type': "Microsoft.RecoveryServices/vaults",
    }
];

const getServiceVault = [
    {
        "id": "/subscriptions/123/resourceGroups/Default-RecoveryServices-ResourceGroup/providers/Microsoft.RecoveryServices/vaults/swaggerExample",
        "type": "Microsoft.RecoveryServices/vaults",
        "sku": {
        "name": "Standard"
        },
        "encryption": {}
    },
    {
        "id": "/subscriptions/123/resourceGroups/Default-RecoveryServices-ResourceGroup/providers/Microsoft.RecoveryServices/vaults/swaggerExample",
        "type": "Microsoft.RecoveryServices/vaults",
        "sku": {
        "name": "Standard"
        },
        "encryption": {
            "keyVaultProperties": {
                "keyUri": 'https://testservicevault.vault.azure.net/keys/testServiceVault'
            },
        }

    }
];

const createCache = (listServiceVault, getServiceVault) => {
    const id = (listServiceVault && listServiceVault.length) ? listServiceVault[0].id : null;
    return {
        recoveryServiceVaults: {
            listBySubscriptionId: {
                'eastus': { data: listServiceVault }
            },
            getRecoveryServiceVault: {
                'eastus': { 
                    [id]: { 
                        data: getServiceVault 
                    }
                }
            }

        },
    };
};

describe('recoveryVaultByokEncrypted', function() {
    describe('run', function() {
        it('should give passing result if no Recovery Service vault found', function(done) {
            const cache = createCache([], null);
            recoveryVaultByokEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Recovery Service Vaults found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for list Recovery Service vault', function(done) {
            const cache = createCache(null, null);
            recoveryVaultByokEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list Recovery Service Vaults:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for get Recovery Service vault', function(done) {
            const cache = createCache([listServiceVaults[0]], null);
            recoveryVaultByokEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for get Recovery Service Vault:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if cmk encryption enabled', function(done) {
            const cache = createCache([listServiceVaults[0]], getServiceVault[1]);
            recoveryVaultByokEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Recovery Service Vault has BYOK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if cmk encryption not enabled', function(done) {
            const cache = createCache([listServiceVaults[0]], getServiceVault[0]);
            recoveryVaultByokEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Recovery Service Vault does not have BYOK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});