var expect = require('chai').expect;
var eventHubDiagnosticLogs = require('./eventHubDiagnosticLogs.js');

const eventHub = [
    {
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
        "name": "testHub",
        "type": 'Microsoft.EventHub/Namespaces',
        "location": 'East US',
        "tags": {},
        "minimumTlsVersion": '1.2',
        "publicNetworkAccess": 'Enabled',
        "disableLocalAuth": true,
        "zoneRedundant": true,
        "isAutoInflateEnabled": false,
        "maximumThroughputUnits": 0,
        "kafkaEnabled": false
    },
];

const diagnosticSettings = [
    {

        "id": "/subscriptions/subid/resourcegroups/rg1/providers/microsoft.eventHub/domains/domain/providers/microsoft.insights/diagnosticSettings/testlogs",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "testlogs",
        "location": null,
        "kind": null,
        "tags": null,
        "storageAccountId": null,
        "logs": [
            {
                "category": "runTime",
                "categoryGroup": null,
                "enabled": true,
            }
        ],
        "logAnalyticsDestinationType": null,

        "identity": null
    }

];

const createCache = (eventHub, ds) => {
    const id = eventHub && eventHub.length ? eventHub[0].id : null;
    return {
        eventHub: {
            listEventHub: {
                'eastus': {
                    data: eventHub
                }
            }
        },
        diagnosticSettings: {
            listByEventHubs: {
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
        eventHub: {
            listEventHub: {
                'eastus': {}
            }
        }
    };
};

describe('eventHubDiagnosticLogs', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for Event Hubs namespaces:', function (done) {
            const cache = createCache(null);
            eventHubDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Event Hubs namespaces:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if No Event Hubs namespaces found', function (done) {
            const cache = createCache([]);
            eventHubDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Event Hubs namespaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([eventHub[0]], null);
            eventHubDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Event Hubs namespace diagnostic settings:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Event Hubs namespace has diagnostic logs enabled', function (done) {
            const cache = createCache([eventHub[0]], [diagnosticSettings[0]]);
            eventHubDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Event Hubs namespace has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Event Hubs namespace does not have diagnostic logs enabled', function (done) {
            const cache = createCache([eventHub[0]],[[]]);
            eventHubDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Event Hubs namespace does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});