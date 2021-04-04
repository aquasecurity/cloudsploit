var expect = require('chai').expect;
var networkAccessDefaultAction = require('./networkAccessDefaultAction');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/aquaacct945c8a10894266bf',
        'name': 'aquaacct945c8a10894266bf',
        'networkAcls': {
            'resourceAccessRules': [],
            'bypass': 'AzureServices',
            'virtualNetworkRules': [],
            'ipRules': [],
            'defaultAction': 'Allow'
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/test-storage',
        'name': 'test-storage',
        'networkAcls': {
            'resourceAccessRules': [],
            'bypass': 'AzureServices',
            'virtualNetworkRules': [],
            'ipRules': [],
            'defaultAction': 'Deny'
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/test-storage',
        'name': 'test-storage',
        'networkAcls': {
            'resourceAccessRules': [],
            'bypass': 'AzureServices',
            'virtualNetworkRules': [],
            'ipRules': [],
            'defaultAction': 'Allow'
        }
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

describe('networkAccessDefaultAction', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts found', function(done) {
            const cache = createCache([]);
            networkAccessDefaultAction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createStorageAccountsErrorCache();
            networkAccessDefaultAction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Storage Account is whitelisted via custom settings', function(done) {
            const cache = createCache([storageAccounts[0]]);
            networkAccessDefaultAction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage account: ' + storageAccounts[0].name + ' is whitelisted via custom setting.');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Storage Account default network access rule set to deny in networkAcls', function(done) {
            const cache = createCache([storageAccounts[1]]);
            networkAccessDefaultAction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Account default network access rule set to deny');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Storage Account default network access rule set to allow from all networks', function(done) {
            const cache = createCache([storageAccounts[2]]);
            networkAccessDefaultAction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage Account default network access rule set to allow from all networks');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});