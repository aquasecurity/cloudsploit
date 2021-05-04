var expect = require('chai').expect;
var storageAccountsHttps = require('./storageAccountsHttps');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/test-storage',
        'name': 'test-storage',
        'supportsHttpsTrafficOnly': true
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/test-storage',
        'name': 'test-storage',
        'supportsHttpsTrafficOnly': false
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

const createStorageAccountsErrorCache = () => {
    return {
        storageAccounts: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('storageAccountsHttps', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts found', function(done) {
            const cache = createCache([]);
            storageAccountsHttps.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createStorageAccountsErrorCache();
            storageAccountsHttps.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Storage Account is configured with HTTPS-only traffic', function(done) {
            const cache = createCache([storageAccounts[0]]);
            storageAccountsHttps.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Account is configured with HTTPS-only traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Storage Account is not configured with HTTPS-only traffic', function(done) {
            const cache = createCache([storageAccounts[1]]);
            storageAccountsHttps.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage Account is not configured with HTTPS-only traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});