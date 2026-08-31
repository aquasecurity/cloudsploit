var expect = require('chai').expect;
var storageAccountEntraIdAuthDefault = require('./storageAccountEntraIdAuthDefault');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'defaultToOAuthAuthentication': true
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'defaultToOAuthAuthentication': false
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

describe('storageAccountEntraIdAuthDefault', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([]);
            storageAccountEntraIdAuthDefault.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            storageAccountEntraIdAuthDefault.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Entra ID authorization is the default', function (done) {
            const cache = createCache([storageAccounts[0]]);
            storageAccountEntraIdAuthDefault.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('defaults to Microsoft Entra authorization');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Entra ID authorization is not the default', function (done) {
            const cache = createCache([storageAccounts[1]]);
            storageAccountEntraIdAuthDefault.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not default to Microsoft Entra authorization');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if defaultToOAuthAuthentication is not set', function (done) {
            const cache = createCache([storageAccounts[2]]);
            storageAccountEntraIdAuthDefault.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not default to Microsoft Entra authorization');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
