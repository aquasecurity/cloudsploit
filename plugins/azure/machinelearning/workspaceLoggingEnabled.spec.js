var expect = require('chai').expect;
var workspaceLoggingEnabled = require('./workspaceLoggingEnabled');

const workspaces = [
    {
        "id": "/subscriptions/12345667/resourceGroups/test/providers/Microsoft.MachineLearningServices/workspaces/test1",
        "name": "test",
        "type": "Microsoft.MachineLearningServices/workspaces",
        "identity": {
            "type": "SystemAssigned"
        }
    
      },
      {
        "id": "/subscriptions/12345667/resourceGroups/test/providers/Microsoft.MachineLearningServices/workspaces/test1",
        "name": "test",
        "type": "Microsoft.MachineLearningServices/workspaces",
        "identity": {
            "type": "None"
        }
      },
];
const diagnosticSettings = [
    {
        id: 'subscriptions/12424/resourceGroups/tets-rg/providers/Microsoft.MachineLearningServices/workspaces/test1/providers/microsoft.insights/diagnosticSettings/test-setting',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'openai-setting',
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
        machineLearning: {
            listWorkspaces: {
                'eastus': {
                    data: workspaces
                }
            }
        },
        diagnosticSettings: {
            listByMachineLearningWorkspce: {
                'eastus': { 
                    [id]: { 
                        data: ds 
                    }
                }
            }

        },
    };
};

describe('workspaceLoggingEnabled', function() {
    describe('run', function() {
        it('should give passing result if no Machine Learning workspace found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Machine Learning workspace found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [],null
            );

            workspaceLoggingEnabled.run(cache, {}, callback);
        });

        it('should give passing result if diagnostic logs is enabled forMachine Learning workspace', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Machine Learning workspace has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [workspaces[0]], [diagnosticSettings[0]]
            );

            workspaceLoggingEnabled.run(cache, {}, callback);
        });

        it('should give failing result if diagnostic logs is not enabled for Machine Learning workspace', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Machine Learning workspace does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [workspaces[0]], []
            );

            workspaceLoggingEnabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for Machine Learning workspaces', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Machine Learning workspaces: ');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null, ['error']);

            workspaceLoggingEnabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Machine Learning workspace diagnostic settings: ');
                expect(results[0].region).to.equal('eastus');
                done();
            };
            const cache = createCache([workspaces[0]], null);
            workspaceLoggingEnabled.run(cache, {}, callback);

        });
    });
});
