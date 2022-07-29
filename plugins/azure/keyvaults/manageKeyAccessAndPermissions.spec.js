var expect = require('chai').expect;
var auth = require('./manageKeyAccessAndPermissions');

const listVaults = [
    {
        id: '/subscriptions/dcsqwwww-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/test',
        name: 'test',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus',
        tags: { owner: 'kubernetes' },
        sku: { family: 'A', name: 'Standard' },
        tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
        accessPolicies: [
          {
            tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
            objectId: '123d1b11-52f8-4dfc-bf08-1b66fa2de1d5',
            permissions: [Object]
          },
          {
            tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
            objectId: 'b4062000-c33b-448b-817e-fa0f17bef4b9',
            permissions: [Object]
          },
          {
            tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
            objectId: '0ef24dfb-2712-44f2-98d2-2df7f946b338',
            permissions: [Object]
          }
        ],
        enabledForDeployment: true,
        enabledForDiskEncryption: true,
        enabledForTemplateDeployment: true,
        enableSoftDelete: true,
        softDeleteRetentionInDays: 7,
        enableRbacAuthorization: false,
        vaultUri: 'https://test.vault.azure.net/',
        provisioningState: 'Succeeded'
    },
    {
        id: '/subscriptions/dcsqwwww-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/akhtar-rg/providers/Microsoft.KeyVault/vaults/test',
        name: 'test',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus',
        tags: { owner: 'kubernetes' },
        sku: { family: 'A', name: 'Standard' },
        tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
        accessPolicies: [
          {
            tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
            objectId: '123d1b11-52f8-4dfc-bf08-1b66fa2de1d5',
            permissions: {
                'certificates': [
                    'Get',
                    'List',
                    'Update',
                    'Create',
                    'Import',
                    'Delete',
                    'Recover',
                    'Backup',
                    'Restore',
                    'ManageContacts',
                    'ManageIssuers',
                    'GetIssuers',
                    'ListIssuers',
                    'SetIssuers',
                    'DeleteIssuers',
                    'Purge'
                ],
                'keys': [
                    'Get',
                    'List',
                    'Update',
                    'Create',
                    'Import',
                    'Delete',
                    'Recover',
                    'Backup',
                    'Restore',
                    'Decrypt',
                    'Encrypt',
                    'UnwrapKey',
                    'WrapKey',
                    'Verify',
                    'Sign',
                    'Purge'
                ],
                'secrets': [
                    'Get',
                    'List',
                    'Set',
                    'Delete',
                    'Recover',
                    'Backup',
                    'Restore',
                    'Purge'
                ],
                'storage': [
                    'get',
                    'list',
                    'delete',
                    'set',
                    'update',
                    'regeneratekey',
                    'setsas',
                    'listsas',
                    'getsas',
                    'deletesas'
                ]
            }
          },
        ],
        enabledForDeployment: true,
        enabledForDiskEncryption: true,
        enabledForTemplateDeployment: true,
        enableSoftDelete: true,
        softDeleteRetentionInDays: 7,
        enableRbacAuthorization: false,
        vaultUri: 'https://test.vault.azure.net/',
        provisioningState: 'Succeeded'
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

describe('manageKeyAccessAndPermissions', function() {
    describe('run', function() {
        it('should give passing result if no key vaults found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [], {}, {}), {}, callback);
        });

        it('should give unkown result if Unable to query for Key Vaults', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, null, {}, {}), {}, callback);
        });

        it('should give passing result if No User/Group or Application has full access to the vault', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No User/Group or Application has full access to the vault');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]]), {}, callback);
        });

        it('should give failing result if a User/Group or Application has full access to the vault', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('User/Group or Application has full access to the vault');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[1]]), {}, callback);
        })
    })
});
