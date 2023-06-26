var expect = require('chai').expect;
var resourceAppropriateSKU = require('./monitorResourceSku');

const resources = [
   {
    id: '/subscriptions/123/resourceGroups/devresourcegroup/providers/Microsoft.Storage/storageAccounts/test-storage-account',
    name: 'test',
    type: 'Microsoft.Storage/storageAccounts',
    sku: { name: 'Standard_LRS', tier: 'Standard' },
    kind: 'StorageV2',
    location: 'eastus',
   },
    {
    id: '/subscriptions/123/resourceGroups/devresourcegroup/providers/Microsoft.Storage/storageAccounts/test-storage-account',
    name: 'test',
    type: 'Microsoft.Storage/storageAccounts',
    sku: { name: 'BASIC', tier: 'BASIC' },
    kind: 'StorageV2',
    location: 'eastus',
   },
];

const createCache = (resource) => {

    return {
        resources: {
            list: {
                'eastus': { data:resource }
            }
        }
    };
};

describe('resourceAppropriateSKU', function() {
    describe('run', function() {
        it('should give passing result if no resource found', function(done) {
            const cache = createCache([]);
            resourceAppropriateSKU.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Resources found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for resource', function(done) {
            const cache = createCache(null);
            resourceAppropriateSKU.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Resources:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if not using basic/consumption SKU', function(done) {
            const cache = createCache([resources[0]]);
            resourceAppropriateSKU.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Resource is using Standard_LRS');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if using basic/consumption SKU', function(done) {
            const cache = createCache([resources[1]]);
            resourceAppropriateSKU.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Resource is using BASIC');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
