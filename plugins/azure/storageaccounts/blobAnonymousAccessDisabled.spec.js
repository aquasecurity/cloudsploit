var expect = require('chai').expect;
var blobAnonymousAccessDisabled = require('./blobAnonymousAccessDisabled');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'allowBlobPublicAccess': false
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'allowBlobPublicAccess': true
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus'
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

describe('blobAnonymousAccessDisabled', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([]);
            blobAnonymousAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            blobAnonymousAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if blob anonymous access is disabled', function (done) {
            const cache = createCache([storageAccounts[0]]);
            blobAnonymousAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has blob anonymous access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if blob anonymous access is enabled', function (done) {
            const cache = createCache([storageAccounts[1]]);
            blobAnonymousAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has blob anonymous access enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if allowBlobPublicAccess is not set', function (done) {
            const cache = createCache([storageAccounts[2]]);
            blobAnonymousAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has blob anonymous access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
