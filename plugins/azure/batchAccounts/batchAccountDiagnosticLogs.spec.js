var expect = require('chai').expect;
var batchAccountDiagnosticLogs = require('./batchAccountDiagnosticLogs');

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
];

const diagnosticSettings = [
    {

        "id": "/subscriptions/subid/resourcegroups/rg1/providers/microsoft.batch/accounts/providers/microsoft.insights/diagnosticSettings/testlogs",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "testlogs",
        "location": null,
        "kind": null,
        "tags": null,
        "storageAccountId": null,
        "logs": [
            {
                "category": "AllLogs",
                "categoryGroup": null,
                "enabled": true,
            }
        ],
        "logAnalyticsDestinationType": null,

        "identity": null
    }

];

const createCache = (batchAccounts, ds) => {
    const id = batchAccounts && batchAccounts.length ? batchAccounts[0].id : null;
    return {
        batchAccounts: {
            list: {
                'eastus': {
                    data: batchAccounts
                }
            }
        },
        diagnosticSettings: {
            listByBatchAccounts: {
                'eastus': {
                    [id]: {
                        data: ds
                    }
                }
            }

        },
    };
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

describe('batchAccountDiagnosticLogs', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for Batch accounts:', function (done) {
            const cache = createCache(null);
            batchAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Batch accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no Batch account exist', function (done) {
            const cache = createCache([]);
            batchAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Batch accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([batchAccounts[0]], null);
            batchAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Batch account diagnostic settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Batch account has diagnostic logs enabled', function (done) {
            const cache = createCache([batchAccounts[0]], [diagnosticSettings[0]]);
            batchAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Batch account has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Batch account does not have diagnostic logs enabled', function (done) {
            const cache = createCache([batchAccounts[0]],[[]]);
            batchAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Batch account does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});