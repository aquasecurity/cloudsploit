var expect = require('chai').expect;
var workspaceDiagnosticLogsEnabled = require('./workspaceDiagnosticLogsEnabled');

const workspaces = [
    {
        type: "Microsoft.Synapse/workspaces",
        id: "/subscriptions/123/resourceGroups/rsgrp/providers/Microsoft.Synapse/workspaces/test",
        location: "eastus",
        name: "test",
    }
];
   
    
const diagnosticSettings = [
    {
        id: "/subscriptions/123/resourceGroups/rsgrp/providers/Microsoft.Synapse/workspaces/test",
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'test',
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

const createCache = (workspaces, ds) => {
    const id = workspaces && workspaces.length ? workspaces[0].id : null;
    return {
        synapse: {
            listWorkspaces: {
                'eastus': {
                    data: workspaces
                }
            }
        },
        diagnosticSettings: {
            listByWorkspaces: {
                'eastus': { 
                    [id]: { 
                        data: ds 
                    }
                }
            }

        },
    };
};

describe('workspaceDiagnosticLogsEnabled', function() {
    describe('run', function() {
        it('should give a passing result if no Synapse workspaces are found', function (done) {
            const cache = createCache([], null);
            workspaceDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Synapse workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Synapse workspaces', function (done) {
            const cache = createCache(null, ['error']);
            workspaceDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Synapse workspaces: Unable to obtain data');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([workspaces[0]], null);
            workspaceDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Synapse workspace diagnostic settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if diagnostic logs enabled', function(done) {
            const cache = createCache([workspaces[0]], [diagnosticSettings[0]]);
            workspaceDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Synapse workspace has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if diagnostic logs not enabled', function(done) {
            const cache = createCache([workspaces[0]], [[]]);
            workspaceDiagnosticLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Synapse workspace does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
