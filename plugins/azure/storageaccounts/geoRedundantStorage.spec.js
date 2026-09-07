var expect = require('chai').expect;
var geoRedundantStorage = require('./geoRedundantStorage');

const account = (skuName) => {
    const acc = {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus'
    };
    if (skuName) acc.sku = { 'name': skuName, 'tier': 'Standard' };
    return acc;
};

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

describe('geoRedundantStorage', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([]);
            geoRedundantStorage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            geoRedundantStorage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if redundancy is Standard_GRS', function (done) {
            const cache = createCache([account('Standard_GRS')]);
            geoRedundantStorage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Standard_GRS which is geo-redundant');
                done();
            });
        });

        it('should give passing result if redundancy is Standard_RAGRS', function (done) {
            const cache = createCache([account('Standard_RAGRS')]);
            geoRedundantStorage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Standard_RAGRS which is geo-redundant');
                done();
            });
        });

        it('should give passing result if redundancy is Standard_GZRS', function (done) {
            const cache = createCache([account('Standard_GZRS')]);
            geoRedundantStorage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Standard_GZRS which is geo-redundant');
                done();
            });
        });

        it('should give passing result if redundancy is Standard_RAGZRS', function (done) {
            const cache = createCache([account('Standard_RAGZRS')]);
            geoRedundantStorage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Standard_RAGZRS which is geo-redundant');
                done();
            });
        });

        it('should give failing result if redundancy is Standard_LRS', function (done) {
            const cache = createCache([account('Standard_LRS')]);
            geoRedundantStorage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Standard_LRS which is not geo-redundant');
                done();
            });
        });

        it('should give failing result if redundancy is Standard_ZRS', function (done) {
            const cache = createCache([account('Standard_ZRS')]);
            geoRedundantStorage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Standard_ZRS which is not geo-redundant');
                done();
            });
        });

        it('should give unknown result if sku is not present', function (done) {
            const cache = createCache([account(null)]);
            geoRedundantStorage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to determine Storage Account redundancy setting');
                done();
            });
        });
    });
});
