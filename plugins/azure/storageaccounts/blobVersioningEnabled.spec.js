var expect = require('chai').expect;
var blobVersioningEnabled = require('./blobVersioningEnabled');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus'
    }
];

const serviceProperties = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default',
        'isVersioningEnabled': true
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default',
        'isVersioningEnabled': false
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default'
    }
];

const createCache = (storageAccounts, serviceProps, servicePropsErr) => {
    const accountId = storageAccounts && storageAccounts.length ? storageAccounts[0].id : null;
    const propsObj = {};
    if (accountId) {
        if (servicePropsErr) {
            propsObj[accountId] = { err: servicePropsErr };
        } else if (serviceProps) {
            propsObj[accountId] = { data: serviceProps };
        }
    }
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    data: storageAccounts
                }
            }
        },
        blobServices: {
            getServiceProperties: {
                'eastus': propsObj
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

describe('blobVersioningEnabled', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([], null);
            blobVersioningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            blobVersioningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to get blob service properties', function (done) {
            const cache = createCache(storageAccounts, null, ['Forbidden']);
            blobVersioningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get blob service properties');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if blob versioning is enabled', function (done) {
            const cache = createCache(storageAccounts, serviceProperties[0]);
            blobVersioningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Blob versioning is enabled for Storage Account');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if blob versioning is disabled', function (done) {
            const cache = createCache(storageAccounts, serviceProperties[1]);
            blobVersioningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Blob versioning is not enabled for Storage Account');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if versioning setting is not present', function (done) {
            const cache = createCache(storageAccounts, serviceProperties[2]);
            blobVersioningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Blob versioning is not enabled for Storage Account');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
