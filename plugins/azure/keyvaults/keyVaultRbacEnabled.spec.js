var expect = require('chai').expect;
var keyVaultRbacEnabled = require('./keyVaultRbacEnabled');

const vaults = [
    {
        'name': 'test-vault',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.KeyVault/vaults/test-vault',
        'type': 'Microsoft.KeyVault/vaults',
        'location': 'eastus',
        'enableRbacAuthorization': true
    },
    {
        'name': 'test-vault',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.KeyVault/vaults/test-vault',
        'type': 'Microsoft.KeyVault/vaults',
        'location': 'eastus',
        'enableRbacAuthorization': false
    },
    {
        'name': 'test-vault',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.KeyVault/vaults/test-vault',
        'type': 'Microsoft.KeyVault/vaults',
        'location': 'eastus'
    }
];

const createCache = (vaults) => {
    return {
        vaults: {
            list: {
                'eastus': {
                    data: vaults
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        vaults: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('keyVaultRbacEnabled', function () {
    describe('run', function () {
        it('should give passing result if no Key Vaults found', function (done) {
            const cache = createCache([]);
            keyVaultRbacEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Key Vaults', function (done) {
            const cache = createErrorCache();
            keyVaultRbacEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Key Vault has RBAC authorization enabled', function (done) {
            const cache = createCache([vaults[0]]);
            keyVaultRbacEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key Vault has RBAC authorization enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Key Vault does not have RBAC authorization enabled', function (done) {
            const cache = createCache([vaults[1]]);
            keyVaultRbacEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vault does not have RBAC authorization enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if RBAC authorization setting is not present', function (done) {
            const cache = createCache([vaults[2]]);
            keyVaultRbacEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vault does not have RBAC authorization enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
