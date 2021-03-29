var expect = require('chai').expect;
var trustedMsAccessEnabled = require('./trustedMsAccessEnabled');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'networkAcls': {
            'bypass': 'AzureServices'
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'networkAcls': {
            'bypass': 'None'
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

const createErrorCache = () => {
    return {
        storageAccounts: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('trustedMsAccessEnabled', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([]);
            trustedMsAccessEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createErrorCache();
            trustedMsAccessEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if trusted MS access is enabled', function(done) {
            const cache = createCache([storageAccounts[0]]);
            trustedMsAccessEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Account is set to allow trusted Microsoft services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if trusted MS access is not enabled', function(done) {
            const cache = createCache([storageAccounts[1]]);
            trustedMsAccessEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage Account is not set to allow trusted Microsoft services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});