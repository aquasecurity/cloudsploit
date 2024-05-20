var expect = require('chai').expect;
var batchAccountCmkEncrypted = require('./batchAccountCmkEncrypted.js');

const batchAccounts = [
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test",
        "name": "test",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
        "provisioningState": "Succeeded",
        "dedicatedCoreQuota": 6,
        "encryption": {
            "keySource": "Microsoft.Batch"
          },
    },
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test",
        "name": "test",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
        "provisioningState": "Succeeded",
        "dedicatedCoreQuota": 6,
        "encryption": {
            "keySource": "Microsoft.KeyVault",
            "keyVaultProperties": {
                "keyIdentifier": "https://test.vault.azure.net/keys/testkey/1"
              }
          },
    }
];

const createCache = (batchAccounts,err) => {
    return {
        batchAccounts: {
            list: {
                'eastus': {
                    data: batchAccounts,
                    err: err
                }
            }
        }
    }
};

describe('batchAccountCmkEncrypted', function () {
    describe('run', function () {

        it('should give pass result if No existing batch accounts found', function (done) {
            const cache = createCache([]);
            batchAccountCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Batch accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query batch accounts:', function (done) {
            const cache = createCache(null, 'Error');
            batchAccountCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Batch accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if batch account is encrypted using CMK', function (done) {
            const cache = createCache([batchAccounts[1]]);
            batchAccountCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Batch account is encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if batch account is not encrypted using CMK', function (done) {
            const cache = createCache([batchAccounts[0]]);
            batchAccountCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Batch account is not encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});