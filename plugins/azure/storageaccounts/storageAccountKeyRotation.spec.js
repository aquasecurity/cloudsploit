var expect = require('chai').expect;
var storageAccountKeyRotation = require('./storageAccountKeyRotation');

const daysAgo = (days) => {
    const date = new Date();
    date.setDate(date.getDate() - days);
    return date.toISOString();
};

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'keyCreationTime': {
            'key1': daysAgo(10),
            'key2': daysAgo(10)
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'keyCreationTime': {
            'key1': daysAgo(200),
            'key2': daysAgo(200)
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'keyCreationTime': {
            'key1': daysAgo(10),
            'key2': daysAgo(200)
        }
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

describe('storageAccountKeyRotation', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([]);
            storageAccountKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            storageAccountKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if keys were rotated within the desired limit', function (done) {
            const cache = createCache([storageAccounts[0]]);
            storageAccountKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('equal to or less than 90 days limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if keys were not rotated within the desired limit', function (done) {
            const cache = createCache([storageAccounts[1]]);
            storageAccountKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('more than 90 days limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if only one key is outdated', function (done) {
            const cache = createCache([storageAccounts[2]]);
            storageAccountKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('more than 90 days limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if keys have never been rotated', function (done) {
            const cache = createCache([storageAccounts[3]]);
            storageAccountKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('have never been rotated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
