var expect = require('chai').expect;
var storageAccountPublicNetworkAccess = require('./storageAccountPublicNetworkAccess');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'tags': { 'key': 'value' },
        "publicNetworkAccess": "Disabled"
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'tags': {},
        "publicNetworkAccess": "Enabled"
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

describe('storageAccountPublicNetworkAccess', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([]);
            storageAccountPublicNetworkAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createErrorCache();
            storageAccountPublicNetworkAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Storage account has public network access disabled', function(done) {
            const cache = createCache([storageAccounts[0]]);
            storageAccountPublicNetworkAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage account has public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Storage account has public network access disabled', function(done) {
            const cache = createCache([storageAccounts[1]]);
            storageAccountPublicNetworkAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage account does not have public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});