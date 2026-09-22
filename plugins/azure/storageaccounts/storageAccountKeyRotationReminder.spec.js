var expect = require('chai').expect;
var storageAccountKeyRotationReminder = require('./storageAccountKeyRotationReminder');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'keyPolicy': {
            'keyExpirationPeriodInDays': 90
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'keyPolicy': {
            'keyExpirationPeriodInDays': 180
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

describe('storageAccountKeyRotationReminder', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([]);
            storageAccountKeyRotationReminder.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            storageAccountKeyRotationReminder.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if reminder period is within the desired limit', function (done) {
            const cache = createCache([storageAccounts[0]]);
            storageAccountKeyRotationReminder.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('key rotation reminder is set to 90 days');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if reminder period exceeds the desired limit', function (done) {
            const cache = createCache([storageAccounts[1]]);
            storageAccountKeyRotationReminder.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('key rotation reminder is set to 180 days which is greater than 90 days');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if key rotation reminder is not enabled', function (done) {
            const cache = createCache([storageAccounts[2]]);
            storageAccountKeyRotationReminder.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have key rotation reminder enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
