var expect = require('chai').expect;
var automationAccountDiagnosticLogs = require('./automationAcctDiagnosticLogs.js');

const automationAccounts = [
    {
        "id": "/subscriptions/12345/resourceGroups/DefaultResourceGroup-EUS/providers/Microsoft.Automation/automationAccounts/Automate-12345-EUS2",
        "location": "EastUS2",
        "name": "Automate-12345-EUS2",
        "type": "Microsoft.Automation/AutomationAccounts",
        "tags": {},
        "properties": {
          "creationTime": "2023-10-27T07:27:02.76+00:00",
          "lastModifiedTime": "2023-10-27T07:27:02.76+00:00"
        }
    },
    {
        "id": "/subscriptions/12345/resourceGroups/DefaultResourceGroup-CUS/providers/Microsoft.Automation/automationAccounts/Automate-12345-CUS",
        "location": "centralus",
        "name": "Automate-12345-CUS",
        "type": "Microsoft.Automation/AutomationAccounts",
        "tags": {},
        "properties": {
          "creationTime": "2023-07-17T13:09:21.4866667+00:00",
          "lastModifiedTime": "2023-07-17T13:09:21.4866667+00:00"
        }
    }
];

const diagnosticSettings = [
    {
        id: '/subscriptions/12345/resourcegroups/cloudsploit-dev/providers/microsoft.cdn/automationAccounts/omer-cdn-profile-test/providers/microsoft.insights/diagnosticSettings/testaccesslogs',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'testaccesslogs',
        location: 'global',
        logs: [
            {
                "category": "JobLogs",
                "categoryGroup": null,
                "enabled": true,
                "retentionPolicy": {
                  "enabled": false,
                  "days": 0
                }
              },
          ],
          "logAnalyticsDestinationType": null
    },
    {
        id: '/subscriptions/12345/resourcegroups/cloudsploit-dev/providers/microsoft.cdn/automationAccounts/omer-cdn-profile-test/providers/microsoft.insights/diagnosticSettings/testaccesslogs',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'testwaflogs',
        location: 'global',
        logs: [
            {
              "category": "JobLogs",
              "categoryGroup": null,
              "enabled": true,
              "retentionPolicy": {
                "enabled": false,
                "days": 0
              }
            },
            {
                "category": "JobStreams",
                "categoryGroup": null,
                "enabled": true,
                "retentionPolicy": {
                  "enabled": false,
                  "days": 0
                }
            },
            {
                "category": "DscNodeStatus",
                "categoryGroup": null,
                "enabled": true,
                "retentionPolicy": {
                  "enabled": false,
                  "days": 0
                }
            },
            {
                "category": "AuditEvent",
                "categoryGroup": null,
                "enabled": true,
                "retentionPolicy": {
                  "enabled": false,
                  "days": 0
                }
            },
            
          ],
          "logAnalyticsDestinationType": null
    },
    {},
    {
        id: '/subscriptions/12345/resourcegroups/cloudsploit-dev/providers/microsoft.cdn/automationAccounts/omer-cdn-profile-test/providers/microsoft.insights/diagnosticSettings/testaccesslogs',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'testwaflogs',
        location: 'global',
        logs: [
            {
              "category": "",
              "categoryGroup": "allLogs",
              "enabled": true,
              "retentionPolicy": {
                "enabled": false,
                "days": 0
              }
            }
          ],
          "logAnalyticsDestinationType": null
    },
    {
        id: '/subscriptions/12345/resourcegroups/cloudsploit-dev/providers/microsoft.cdn/automationAccounts/omer-cdn-profile-test/providers/microsoft.insights/diagnosticSettings/testaccesslogs',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'testwaflogs',
        location: 'global',
        logs: [
            {
                "category": "DummyCategory",
                "categoryGroup": "",
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

const createCache = (automationAccounts, diagnostics) => {
    let diagnostic = {};
    if (automationAccounts.length) {
        diagnostic[automationAccounts[0].id] = {
            data: diagnostics
        };
    }


    return {
        automationAccounts: {
            list: {
                'eastus': {
                    data: automationAccounts
                }
            }
        },
        diagnosticSettings: {
            listByAutomationAccounts: {
                'eastus': diagnostic
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key == 'unknownaccount') {
        return {
            automationAccounts: {
                list: {
                    'eastus': {}
                }
            }
        };
    } else if (key === 'noaccounts'){
        return {
            automationAccounts: {
                list: {
                    'eastus': {
                        data:{}
                    }
                }
            }
        };
    }else if (key === 'diagnostic') {
        return {
            automationAccounts: {
                list: {
                    'global': {
                        data: [automationAccounts[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByAutomationAccounts: {
                    'global': {}
                }
            }
        };
    } else {
        const accountId = (automationAccounts && automationAccounts.length) ? automationAccounts[0].id : null;
        const diagnosticSetting = (diagnosticSettings && diagnosticSettings.length) ? diagnosticSettings[0].id : null;
        return {
            automationAccounts: {
                list: {
                    'eastus': {
                        data: [automationAccounts[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByAutomationAccounts: {
                    'eastus': {
                        data: {}
                    }
                }
            }
        };
    }
};

describe('automationAccountDiagnosticLogs', function () {
    describe('run', function () {

        it('should give pass result if No existing automation accounts found', function (done) {
            const cache = createErrorCache('noaccounts');
            automationAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Automation accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation accounts:', function (done) {
            const cache = createErrorCache('unknownaccount');
            automationAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query diagnostics settings', function (done) {
            const cache = createErrorCache('policy');
            automationAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation account diagnostic settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if automation account has diagnostic logging enabled', function (done) {
            const cache = createCache([automationAccounts[0]], [diagnosticSettings[1]]);
            automationAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation account has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if automation account does not have diagnostic logging enabled', function (done) {
            const cache = createCache([automationAccounts[1]], [diagnosticSettings[0]]);
            automationAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automation account does not have diagnostic logs enabled for following');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give pass result if automation account have allLogs Enabled', function(done) {
            const cache = createCache([automationAccounts[1]], [diagnosticSettings[3]]);
            automationAccountDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation account has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result with * setting', function (done) {
            const cache = createCache([automationAccounts[1]], [diagnosticSettings[4]]);
            automationAccountDiagnosticLogs.run(cache, {diagnostic_logs: '*'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation account has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Automation Account does not have diagnostic logs enabled with settings', function (done) {
            const cache = createCache([automationAccounts[1]], [diagnosticSettings[1]]);
            automationAccountDiagnosticLogs.run(cache, {diagnostic_logs: 'testsetting'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automation account does not have diagnostic logs enabled for following:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});