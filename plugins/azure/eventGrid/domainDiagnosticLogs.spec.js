var expect = require('chai').expect;
var domainDiagnosticLogs = require('./domainDiagnosticLogs');

const eventGridDomains = [
    {
        "properties": {
            "endpoint": "https://exampledomain1.westus2-1.eventgrid.azure.net/api/events",
            "provisioningState": "Succeeded"
          },
          "id": "/subscriptions/1234/resourceGroups/examplerg/providers/Microsoft.EventGrid/domains/exampledomain1",
          "location": "westus2",
          "name": "exampledomain1",
          "publicNetworkAccess": "Enabled"
    }
];

const diagnosticSettings = [
    {

        "id": "/subscriptions/subid/resourcegroups/rg1/providers/microsoft.eventgrid/domains/domain/providers/microsoft.insights/diagnosticSettings/testlogs",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "testlogs",
        "location": null,
        "kind": null,
        "tags": null,
        "storageAccountId": null,
        "logs": [
            {
                "category": "deliveryFailureLogs",
                "categoryGroup": null,
                "enabled": true,
            }
        ],
        "logAnalyticsDestinationType": null,

        "identity": null
    }

];

const createCache = (eventGridDomains, ds) => {
    const id = eventGridDomains && eventGridDomains.length ? eventGridDomains[0].id : null;
    return {
        eventGrid: {
            listDomains: {
                'eastus': {
                    data: eventGridDomains
                }
            }
        },
        diagnosticSettings: {
            listByEventGridDomains: {
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
        eventGrid: {
            listDomains: {
                'eastus': {}
            }
        }
    };
};

describe('domainDiagnosticLogs', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for Event Grid domains:', function (done) {
            const cache = createCache(null);
            domainDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Event Grid domains:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no event grid domains exist', function (done) {
            const cache = createCache([]);
            domainDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Event Grid domains found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([eventGridDomains[0]], null);
            domainDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Event Grid domains diagnostic settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Event Grid domain has diagnostic logs enabled', function (done) {
            const cache = createCache([eventGridDomains[0]], [diagnosticSettings[0]]);
            domainDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Event Grid domain has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Event Grid domain does not have diagnostic logs enabled', function (done) {
            const cache = createCache([eventGridDomains[0]],[[]]);
            domainDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Event Grid domain does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});