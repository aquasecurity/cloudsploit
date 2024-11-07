var expect = require('chai').expect;
var appConfigurationDiagnosticLogs = require('./appConfigurationDiagnosticLogs');

const appConfigurations = [
    {
        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedappConfigurations/absbaks2",
    },
];
   
    
const diagnosticSettings = [
    {
        id: '/subscriptions/234/myrg/providers/Microsoft.ContainerService/appConfigurations/absbaks2/providers/microsoft.insights/diagnosticSettings/test-setting',
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

const createCache = (appConfigurations, ds) => {
    const id = appConfigurations && appConfigurations.length ? appConfigurations[0].id : null;
    return {
        appConfigurations: {
            list: {
                'eastus': {
                    data: appConfigurations
                }
            }
        },
        diagnosticSettings: {
            listByAppConfigurations: {
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
        appConfigurations: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('appConfigurationDiagnosticLogs', function() {
    describe('run', function() {
        it('should give pass result if No existing app configurations found', function (done) {
            const cache = createCache([]);
            appConfigurationDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Configurations found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query app configurations:', function (done) {
            const cache = createCache(null, 'Error');
            appConfigurationDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Configuration:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([appConfigurations[0]], null);
            appConfigurationDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Configuration diagnostic settings:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if diagnostic logs enabled', function(done) {
            const cache = createCache([appConfigurations[0]], [diagnosticSettings[0]]);
            appConfigurationDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Configuration has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if diagnostic logs not enabled', function(done) {
            const cache = createCache([appConfigurations[0]], [[]]);
            appConfigurationDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Configuration does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});