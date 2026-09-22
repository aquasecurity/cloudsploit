var expect = require('chai').expect;
var keyVaultKeyRotation = require('./keyVaultKeyRotation');

const vaults = [
    {
        'name': 'test-vault',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.KeyVault/vaults/test-vault',
        'type': 'Microsoft.KeyVault/vaults',
        'location': 'eastus'
    }
];

const keyId = '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.KeyVault/vaults/test-vault/keys/test-key';

const keys = [
    { 'id': keyId },
    { 'id': keyId },
    { 'id': keyId }
];

const keyDetails = [
    {
        'rotationPolicy': {
            'lifetimeActions': [
                {
                    'trigger': { 'timeAfterCreate': 'P90D' },
                    'action': { 'type': 'rotate' }
                },
                {
                    'trigger': { 'timeBeforeExpiry': 'P30D' },
                    'action': { 'type': 'notify' }
                }
            ],
            'attributes': { 'expiryTime': 'P2Y' }
        }
    },
    {
        'rotationPolicy': {
            'lifetimeActions': [
                {
                    'trigger': { 'timeBeforeExpiry': 'P30D' },
                    'action': { 'type': 'notify' }
                }
            ]
        }
    },
    {}
];

const createCache = (vaults, keys, keysErr, detailIndex) => {
    const vaultId = vaults && vaults.length ? vaults[0].id : null;
    const keyObj = {};
    const detailObj = {};
    if (vaultId) {
        keyObj[vaultId] = keysErr ? { err: keysErr } : { data: keys };
        if (keys && keys.length && detailIndex !== undefined && keyDetails[detailIndex]) {
            detailObj[keyId] = { data: keyDetails[detailIndex] };
        }
    }
    return {
        vaults: {
            list: {
                'eastus': {
                    data: vaults
                }
            },
            listKeys: {
                'eastus': keyObj
            }
        },
        getKey: {
            get: {
                'eastus': detailObj
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

describe('keyVaultKeyRotation', function () {
    describe('run', function () {
        it('should give passing result if no Key Vaults found', function (done) {
            const cache = createCache([], null);
            keyVaultKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Key Vaults', function (done) {
            const cache = createErrorCache();
            keyVaultKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Key Vault keys', function (done) {
            const cache = createCache(vaults, null, ['ForbiddenByRbac']);
            keyVaultKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vault keys');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no keys found in vault', function (done) {
            const cache = createCache(vaults, []);
            keyVaultKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Key Vault keys found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if key has automatic rotation enabled', function (done) {
            const cache = createCache(vaults, [keys[0]], null, 0);
            keyVaultKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key Vault key has automatic rotation enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if key only has a notify action', function (done) {
            const cache = createCache(vaults, [keys[1]], null, 1);
            keyVaultKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vault key does not have automatic rotation enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if key has no rotation policy', function (done) {
            const cache = createCache(vaults, [keys[2]], null, 2);
            keyVaultKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vault key does not have automatic rotation enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for the key', function (done) {
            const cache = createCache(vaults, [keys[0]]);
            keyVaultKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vault key');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
