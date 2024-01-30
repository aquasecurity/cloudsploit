var expect = require('chai').expect;
var appServiceDiagnosticLogs = require('./appServiceDiagnosticLogs');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'kind': 'functionapp',
        'location': 'East US'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'kind': 'functionapp',
        'location': 'East US'
    }
];

const diagnosticSettings = [
    {
        "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "app-ds",
        "logs": [
          {
            "category": "FunctionAppLogs",
            "categoryGroup": null,
            "enabled": true,
            "retentionPolicy": {
              "enabled": false,
              "days": 0
            }
          }
        ],
        "logAnalyticsDestinationType": null
    },
]

const createCache = (webApps, diagnostics) => {
    let ds = {};
    if (webApps.length) {
        ds[webApps[0].id] = {
            data: diagnostics
        };
    }

    return {
        webApps: {
            list: {
                'eastus': {
                    data: webApps
                }
            }
        },
        diagnosticSettings: {
            listByAppServices: {
                'eastus': ds
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key === 'webApp') {
        return {
            webApps: {
                list: {
                    'eastus': {}
                }
            }
        };
    } else if (key === 'noWebApp'){
        return {
            webApps: {
                list: {
                    'eastus': {
                        data:{}
                    }
                }
            }
        };
    }else if (key === 'diagnostic') {
        return {
            webApps: {
                list: {
                    'eastus': {
                        data: [webApps[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByAppServices: {
                    'eastus': {}
                }
            }
        };
    } else {
        const appId = (webApps && webApps.length) ? webApps[0].id : null;
        const diagnosticSetting = (diagnosticSettings && diagnosticSettings.length) ? diagnosticSettings[0].id : null;
        return {
            webApps: {
                list: {
                    'eastus': {
                        data: [appId[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByAppServices: {
                    'eastus': {
                        data: {}
                    }
                }
            }
        };
    }
};

describe('appServiceDiagnosticLogs', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            appServiceDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Web Apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web apps', function(done) {
            const cache = createErrorCache('webApp');
            appServiceDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web Apps');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createErrorCache('diagnostic');
            appServiceDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Service diagnostic settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if diagnostic logs enabled', function(done) {
            const cache = createCache([webApps[0]], [diagnosticSettings[0]]);
            appServiceDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Service has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if diagnostic logs not enabled', function(done) {
            const cache = createCache([webApps[0]], [[]]);
            appServiceDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Service does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
