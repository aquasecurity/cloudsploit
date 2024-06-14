
var expect = require('chai').expect;
var batchAccountsManagedIdentity = require('./batchAccountsManagedIdentity');

const batchAccounts = [
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test",
        "name": "test",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
        "identity": {
            "principalId": "6bb43e0b-f260-4a69-ba3b-853b14451327",
            "tenantId": "d207c7bd-fcb1-4dd3-855a-cfd2f9b651e8",
            "type": "SystemAssigned",
        }
    },
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test",
        "name": "test",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
    },
];

const createCache = (batchAccounts) => {
    return {
        batchAccounts: {
            list: {
                'eastus': {
                    data: batchAccounts
                }
            }
        }
    }
};

const createErrorCache = () => {
    return {
        batchAccounts: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('batchAccountsManagedIdentity', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for Batch accounts:', function (done) {
            const cache = createCache(null);
            batchAccountsManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Batch accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no Batch account exist', function (done) {
            const cache = createCache([]);
            batchAccountsManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Batch accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Batch account has managed identity enabled', function (done) {
            const cache = createCache([batchAccounts[0]]);
            batchAccountsManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Batch account has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Batch account does not have managed identity enabled', function (done) {
            const cache = createCache([batchAccounts[1]]);
            batchAccountsManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Batch account does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});