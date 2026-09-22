var expect = require('chai').expect;
var containerSoftDeletionEnabled = require('./containerSoftDeletionEnabled');

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
        'containerDeleteRetentionPolicy': {
            'enabled': true,
            'days': 30
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default',
        'containerDeleteRetentionPolicy': {
            'enabled': true,
            'days': 3
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default',
        'containerDeleteRetentionPolicy': {
            'enabled': false
        }
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

describe('containerSoftDeletionEnabled', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([], null);
            containerSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            containerSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to get blob service properties', function (done) {
            const cache = createCache(storageAccounts, null, ['Forbidden']);
            containerSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get blob service properties');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if retention days meet the desired limit', function (done) {
            const cache = createCache(storageAccounts, serviceProperties[0]);
            containerSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('persist deleted containers for 30 of 7 days desired limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if retention days are less than the desired limit', function (done) {
            const cache = createCache(storageAccounts, serviceProperties[1]);
            containerSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('persist deleted containers for 3 of 7 days desired limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if soft delete is disabled', function (done) {
            const cache = createCache(storageAccounts, serviceProperties[2]);
            containerSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Containers soft delete feature is not enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no container delete retention policy exists', function (done) {
            const cache = createCache(storageAccounts, serviceProperties[3]);
            containerSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Containers soft delete feature is not enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
