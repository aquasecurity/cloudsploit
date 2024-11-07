var expect = require('chai').expect;
var aksDiagnosticLogsEnabled = require('./aksDiagnosticLogsEnabled');

const clusters = [
    {
        "id": "/subscriptions/123-test/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedClusters/absbaks2",
    },
];
   
    
const diagnosticSettings = [
    {
        id: '/subscriptions/234/myrg/providers/Microsoft.ContainerService/managedClusters/absbaks2/providers/microsoft.insights/diagnosticSettings/test-setting',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'server-setting',
        location: 'eastus',
        kind: null,
        tags: null,
        eventHubName: null,
        metrics: [],
        logs: [
            {
              "category": null,
              "categoryGroup": "allLogs",
              "enabled": true,
              "retentionPolicy": {
                "enabled": false,
                "days": 0
              }
            },
            {
              "category": null,
              "categoryGroup": "audit",
              "enabled": false,
              "retentionPolicy": {
                "enabled": false,
                "days": 0
              }
            }
          ],
        logAnalyticsDestinationType: null
    }
];

const createCache = (clusters, ds) => {
    const id = clusters && clusters.length ? clusters[0].id : null;
    return {
        managedClusters: {
            list: {
                'eastus': {
                    data: clusters
                }
            }
        },
        diagnosticSettings: {
            listByAksClusters: {
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
        managedClusters: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('aksDiagnosticLogsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no clusters', function(done) {
            const cache = createCache([]);
            aksDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Kubernetes clusters');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for kubernetes clusters', function(done) {
            const cache = createErrorCache();
            aksDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Kubernetes clusters: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([clusters[0]], null);
            aksDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Kubernetes cluster diagnostic settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if diagnostic logs enabled', function(done) {
            const cache = createCache([clusters[0]], [diagnosticSettings[0]]);
            aksDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('AKS cluster has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if diagnostic logs not enabled', function(done) {
            const cache = createCache([clusters[0]], [[]]);
            aksDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('AKS cluster does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
