var expect = require('chai').expect;
var amsDiagnosticLogsEnabled = require('./amsDiagnosticLogsEnabled');

const mediaServices = [
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Media/mediaservices/test',
        "type": 'Microsoft.Media/mediaservices',
        "location": 'eastus',
        "publicNetworkAccess": 'Enabled',
        "provisioningState": 'Succeeded',
        "privateEndpointConnections": [],
        "minimumTlsVersion": 'Tls12'
    }
];

const diagnosticSettings = [
    {
        id: '/subscriptions/123/resourceGroups/aqua-resource-group/providers/microsoft.media/mediaservices/test/providers/microsoft.insights/diagnosticSettings/test2',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'test2',
        location: 'eastus',
        kind: null,
        tags: null,
        eventHubName: null,
        metrics: [],
        logs: [
            {
                category: null,
                categoryGroup: 'audit',
                enabled: false,
                retentionPolicy: { enabled: false, days: 0 }
            },
            {
                category: null,
                categoryGroup: 'allLogs',
                enabled: true,
                retentionPolicy: { enabled: false, days: 0 }
            }
        ],
        logAnalyticsDestinationType: null
    },
    {
        id: '/subscriptions/123/resourceGroups/aqua-resource-group/providers/microsoft.media/mediaservices/test/providers/microsoft.insights/diagnosticSettings/test2',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'test2',
        location: 'eastus',
        kind: null,
        tags: null,
        identity: null,
        metrics: [],
        logs: [],
        logAnalyticsDestinationType: null
    },
];

const createCache = (ams, ds) => {
    const id = (ams && ams.length) ? ams[0].id : null;
    return {
        mediaServices: {
            listAll: {
                'eastus': {
                    data: ams
                }
            }
        },
        diagnosticSettings: {
            listByMediaService: {
                'eastus': { 
                    [id]: { 
                        data: ds 
                    }
                }
            }

        },
    };
};

describe('amsDiagnosticLogsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no media services found', function(done) {
            const cache = createCache([], null);
            amsDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Media Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for media services', function(done) {
            const cache = createCache(null, null);
            amsDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Media Services:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([mediaServices[0]], null);
            amsDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Media Service diagnostic settings:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if diagnostic logs enabled', function(done) {
            const cache = createCache([mediaServices[0]], [diagnosticSettings[0]]);
            amsDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Media Service has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if diagnostic logs not enabled', function(done) {
            const cache = createCache([mediaServices[0]], [diagnosticSettings[1]]);
            amsDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Media Service does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
