
var expect = require('chai').expect;
var batchAccountsAADEnabled = require('./batchAccountsAADEnabled');

const batchAccounts = [
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test",
        "name": "test",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
        "allowedAuthenticationModes": ["SharedKey", "AAD", "TaskAuthenticationToken"]
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

describe('batchAccountsAADEnabled', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for Batch accounts:', function (done) {
            const cache = createCache(null);
            batchAccountsAADEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Batch accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no Batch account exist', function (done) {
            const cache = createCache([]);
            batchAccountsAADEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Batch accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Batch account is configured with AAD Authentication', function (done) {
            const cache = createCache([batchAccounts[0]]);
            batchAccountsAADEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Batch account is configured with AAD Authentication');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Batch account is not configured with AAD Authentication', function (done) {
            const cache = createCache([batchAccounts[1]]);
            batchAccountsAADEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Batch account is not configured with AAD Authentication');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});