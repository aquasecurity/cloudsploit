var expect = require('chai').expect;
var fileShareSoftDeletionEnabled = require('./fileShareSoftDeletionEnabled');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus'
    }
];

const fileServiceProperties = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/fileServices/default',
        'shareDeleteRetentionPolicy': {
            'enabled': true,
            'days': 30
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/fileServices/default',
        'shareDeleteRetentionPolicy': {
            'enabled': true,
            'days': 3
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/fileServices/default',
        'shareDeleteRetentionPolicy': {
            'enabled': false
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/fileServices/default'
    }
];

const createCache = (storageAccounts, serviceProperties, servicePropertiesErr) => {
    const accountId = storageAccounts && storageAccounts.length ? storageAccounts[0].id : null;
    const propsObj = {};
    if (accountId) {
        if (servicePropertiesErr) {
            propsObj[accountId] = { err: servicePropertiesErr };
        } else if (serviceProperties) {
            propsObj[accountId] = { data: serviceProperties };
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
        fileServices: {
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

describe('fileShareSoftDeletionEnabled', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([], null);
            fileShareSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            fileShareSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to get file service properties', function (done) {
            const cache = createCache(storageAccounts, null, ['Forbidden']);
            fileShareSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get file service properties');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if retention days meet the desired limit', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[0]);
            fileShareSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('persist deleted file shares for 30 of 7 days desired limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if retention days are less than the desired limit', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[1]);
            fileShareSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('persist deleted file shares for 3 of 7 days desired limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if soft delete is disabled', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[2]);
            fileShareSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('File shares soft delete feature is not enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no share delete retention policy exists', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[3]);
            fileShareSoftDeletionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('File shares soft delete feature is not enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
