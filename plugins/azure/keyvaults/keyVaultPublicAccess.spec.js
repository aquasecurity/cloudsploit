var expect = require('chai').expect;
var keyVaultPublicAccess = require('./keyVaultPublicAccess');

const vaults = [
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.KeyVault/vaults/test1",
        "name": "test1",
        "type": "Microsoft.KeyVault/vaults",
        "publicNetworkAccess": "Disabled"

    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.KeyVault/vaults/test2",
        "name": "test2",
        "type": "Microsoft.KeyVault/vaults",
        "publicNetworkAccess": "Enabled",
        "networkAcls": {
            "defaultAction": "Deny",
            "ipRules": [
                {
                    "value": "10.0.0.0/16"
                }
            ]
        }

    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.KeyVault/vaults/test3",
        "name": "test3",
        "type": "Microsoft.KeyVault/vaults",
        "publicNetworkAccess": "Enabled",
        "networkAcls": {
            "defaultAction": "Allow",
            "ipRules": []
        }

    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.KeyVault/vaults/test4",
        "name": "test4",
        "type": "Microsoft.KeyVault/vaults",
        "publicNetworkAccess": "Enabled",
        "networkAcls": {
            "defaultAction": "Deny",
            "ipRules": [
                {
                    "value": "0.0.0.0/0"
                }
            ]
        }
    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.KeyVault/vaults/test6",
        "name": "test6",
        "type": "Microsoft.KeyVault/vaults",
        "publicNetworkAccess": "Enabled"

    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.KeyVault/vaults/test7",
        "name": "test7",
        "type": "Microsoft.KeyVault/vaults",
        "publicNetworkAccess": "Enabled",
        "networkAcls": {
            "defaultAction": "Deny",
            "ipRules": [
                {
                    "value": "192.168.1.1"
                }
            ]

        }
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
                'eastus': {
                    err: {
                        message: 'error loading vaults'
                    }
                }
            }
        }
    };
};

describe('keyVaultPublicAccess', function () {
    describe('run', function () {
        it('should give passing result if no key vaults found', function (done) {
            const cache = createCache([]);
            keyVaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for key vaults', function (done) {
            const cache = createErrorCache();
            keyVaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if public network access is disabled', function (done) {
            const cache = createCache([vaults[0]]);
            keyVaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key Vault is protected from outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if default action is deny and no public IPs allowed', function (done) {
            const cache = createCache([vaults[1]]);
            keyVaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key Vault is protected from outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if default action is allow', function (done) {
            const cache = createCache([vaults[2]]);
            keyVaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vault is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if IPv4 public access is allowed', function (done) {
            const cache = createCache([vaults[3]]);
            keyVaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vault is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no network ACLs configured', function (done) {
            const cache = createCache([vaults[4]]);
            keyVaultPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key Vault is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if IP is in allowed list', function (done) {
            const cache = createCache([vaults[5]]);
            keyVaultPublicAccess.run(cache, { keyvault_allowed_ips: '192.168.1.1' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key Vault is protected from outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 