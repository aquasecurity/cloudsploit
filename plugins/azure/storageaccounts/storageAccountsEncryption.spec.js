var expect = require('chai').expect;
var storageAccountsEncryption = require('./storageAccountsEncryption');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'encryption': {
            'keySource': 'Microsoft.Keyvault'
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'encryption': {
            'keySource': 'Microsoft.Storage'
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
    }  
];

const createCache = (storageAccounts) => {
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    data: storageAccounts
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        storageAccounts: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('storageAccountsEncryption', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([]);
            storageAccountsEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createErrorCache();
            storageAccountsEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if storage account is whitelisted', function(done) {
            const cache = createCache([storageAccounts[2]]);
            storageAccountsEncryption.run(cache, {storage_account_encryption_allow_pattern: 'acc'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage account: acc is whitelisted via custom setting.');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result data-at-rest encryption is configured with Microsoft KeyVault', function(done) {
            const cache = createCache([storageAccounts[0]]);
            storageAccountsEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Account encryption is configured with Microsoft Key vault');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if data-at-rest encryption is configured using Microsoft default storage keys', function(done) {
            const cache = createCache([storageAccounts[1]]);
            storageAccountsEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage Account encryption is configured using Microsoft Default Storage Keys');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if data-at-rest encryption is not configured', function(done) {
            const cache = createCache([storageAccounts[2]]);
            storageAccountsEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage Account is not configured for data-at-rest encryption');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});