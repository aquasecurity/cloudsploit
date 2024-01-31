var expect = require('chai').expect;
var blobContainersCmkEncrypted = require('./blobContainersCmkEncrypted');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'allowBlobPublicAccess': false
    }
];

const blobContainers = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default/containers/container1',
        'location': 'eastus',
        'name': 'container1',
        'publicAccess' : 'None',
        "defaultEncryptionScope": "$account-encryption-key",
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default/containers/container1',
        'location': 'eastus',
        'name': 'container1',
        'publicAccess' : 'Container',
        "defaultEncryptionScope": "testscope",
    }
];

const encryptionScopes = [
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourceGroups/akhtar-function-app_group/providers/Microsoft.Storage/storageAccounts/akhtarfunctionappgrb107/encryptionScopes/testscope",
        "type": "Microsoft.Storage/storageAccounts/encryptionScopes",
        "name": "testscope",
        "source": "Microsoft.Keyvault",
        "keyVaultProperties": {
        "currentVersionedKeyIdentifier": "https://hcicluster.vault.azure.net/keys/test/108d29beff404c0694eab7cc2834f5b6",
        "keyUri": "https://hcicluster.vault.azure.net/keys/test",
        "creationTime": "2024-01-29T12:01:27.7050924Z",
        "lastModifiedTime": "2024-01-29T12:01:27.7050924Z",
        "state": "Enabled"
        }
    },
    {},
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourceGroups/akhtar-function-app_group/providers/Microsoft.Storage/storageAccounts/akhtarfunctionappgrb107/encryptionScopes/testscope",
        "type": "Microsoft.Storage/storageAccounts/encryptionScopes",
        "name": "testscope",
        "source": "Microsoft.Keyvault",
        "source": "Microsoft.Storage",
        "creationTime": "2024-01-29T12:04:34.5251960Z",
        "lastModifiedTime": "2024-01-29T12:04:34.5251960Z",
        "state": "Enabled"
    },
];
const createCache = (storageAccounts, blobContainers, encryptionScopes) => {
    let conatiners = {};
    let scopes = {};
    if (storageAccounts.length) {
        conatiners[storageAccounts[0].id] = {
            data : blobContainers
        };
        scopes[storageAccounts[0].id] = {
            data : encryptionScopes
        };
    }
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    data: storageAccounts
                }
            }
        },
        blobContainers: {
            list: {
                'eastus': conatiners
            }
        },
        encryptionScopes: {
            listByStorageAccounts: {
                'eastus': scopes
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key == 'storageAccount') {
        return {
            storageAccounts: {
                list: {
                    'eastus': {}
                }
            }
        };
    } else if (key == 'unknownEncryptionScopes') {
        let conatiners = {};
        let scopes = {};
        if (storageAccounts.length) {
            conatiners[storageAccounts[0].id] = {
                data : [blobContainers[0]]
            };
            scopes[storageAccounts[0].id] = {
                'err' : 'encryptionError'
            };
        }
        return {
            storageAccounts: {
                list: {
                    'eastus': {
                        data: [storageAccounts[0]]
                    }
                }
            },
            blobContainers: {
                list: {
                    'eastus': conatiners
                }
            },
            encryptionScopes: {
                listByStorageAccounts: {
                   'eastus': scopes
                }
            }
        };
    } 
    else {
        return {
            storageAccounts: {
                list: {
                    'eastus': {
                        data: [storageAccounts[0]]
                    }
                }
            },
            blobContainers: {
                list: {
                    'eastus': {}
                }
            }
        };
    }
};

describe('blobContainersCmkEncrypted', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([], []);
            blobContainersCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Storage Accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no blob containers', function(done) {
            const cache = createCache([storageAccounts[0]], []);
            blobContainersCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Account does not contain blob containers');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createErrorCache('storageAccount');
            blobContainersCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for blob containers', function(done) {
            const cache = createErrorCache('blobContainer');
            blobContainersCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Blob Containers');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknow result if unable to query encryption scopes for Storage Accounts:', function(done) {
            const cache = createErrorCache('unknownEncryptionScopes');
            blobContainersCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query encryption scopes for Storage Accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Blob container does not have CMK encryption enabled', function(done) {
            const cache = createCache([storageAccounts[0]], [blobContainers[0]], [encryptionScopes[0]]);
            blobContainersCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Blob container does not have CMK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Blob container has CMK encryption enabled', function (done) {
            const cache = createCache([storageAccounts[0]], [blobContainers[1]], [encryptionScopes[0]]);
            blobContainersCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Blob container has CMK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

         it('should also give failing result if Blob container does not have CMK encryption enabled', function(done) {
            const cache = createCache([storageAccounts[0]], [blobContainers[0]], [encryptionScopes[1]]);
            blobContainersCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Blob container does not have CMK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        
    });
}); 