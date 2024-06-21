var expect = require('chai').expect;
var workspaceDiagnosticLogs = require('./workspaceDiagnosticLogs.js');

const workspaces = [
    {
        "managedResourceGroupId": "/subscriptions/1234/resourceGroups/test",
        "parameters": {
          "requireInfrastructureEncryption": {
            "type": "Bool",
            "value": false
          },
        },
       "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.Databricks/workspaces/test-workspace",
       "name": "test-workspace",
       "type": "Microsoft.Databricks/workspaces",
       "sku": {
         "name": "trial"
       },
       "location": "eastus",
       "tags": {}
    }
];

const diagnosticSettings = [
    {
        id: '/subscriptions/1234/resourcegroups/cloudsploit-dev/providers/Microsoft.Databricks/workspace/test/providers/microsoft.insights/diagnosticSettings/test',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'test',
        location: null,
        kind: null,
        tags: null,
        identity: null,
        storageAccountId: null,
        serviceBusRuleId: null,
        eventHubAuthorizationRuleId: null,
        eventHubName: null,
        metrics: [ [Object] ],
        logs: [
            {
              category: null,
              categoryGroup: 'allLogs',
              enabled: true,
              retentionPolicy: { enabled: false, days: 0 }
            },
        ],
        logAnalyticsDestinationType: null
    },
    {
        id: '/subscriptions/1234/resourcegroups/cloudsploit-dev/providers/Microsoft.Databricks/workspace/omerredistest/providers/microsoft.insights/diagnosticSettings/test',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'test',
        location: null,
        kind: null,
        tags: null,
        identity: null,
        storageAccountId: null,
        serviceBusRuleId: null,
        eventHubAuthorizationRuleId: null,
        eventHubName: null,
        metrics: [ [Object] ],
        logs: [
        ],
        logAnalyticsDestinationType: null
    }
]
const createCache = (workspace, diagnostics) => {
    let diagnostic = {};
    if (workspace.length) {
        diagnostic[workspace[0].id] = {
            data: diagnostics
        };
    }
    return {
        databricks: {
            listWorkspaces: {
                'eastus': {
                    data: workspace
                }
            }
        },
        diagnosticSettings: {
            listByDatabricksWorkspace: {
                'eastus': diagnostic
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key == 'workspace') {
        return {
            databricks: {
                listWorkspaces: {
                    'eastus': {}
                }
            }
        };
    } else if (key === 'nospace'){
        return {
            databricks: {
                listWorkspaces: {
                    'eastus': {
                        data:{}
                    }
                }
            }
        };
    }else if (key === 'diagnostic') {
        return {
            databricks: {
                listWorkspaces: {
                    'eastus': {
                        data: [workspaces[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByDatabricksWorkspace: {
                    'eastus': {}
                }
            }
        };
    } else {
        const workspaceId = (workspace && workspace.length) ? workspace[0].id : null;
        const diagnosticSetting = (diagnosticSettings && diagnosticSettings.length) ? diagnosticSettings[0].id : null;
        return {
            databricks: {
                listWorkspaces: {
                    'eastus': {
                        data: [workspace[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByDatabricksWorkspace: {
                    'eastus': {
                        data: {}
                    }
                }
            }
        };
    }
};
describe('workspaceDiagnosticLogs', function () {
    describe('run', function () {

        it('should give a passing result if no Databricks workspaces are found', function (done) {
            const cache = createErrorCache('nospace');
            workspaceDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Databricks Workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Databricks workspaces', function (done) {
            const cache = createErrorCache('workspace');
            workspaceDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Databricks Workspaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Databricks workspace diagnostic settings:', function (done) {
            const cache = createErrorCache('diagnostic');
            workspaceDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Databricks workspace diagnostic settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Databricks workspace has diagnostic logs enabled', function (done) {
            const cache = createCache([workspaces[0]],[diagnosticSettings[0]] );
            workspaceDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Databricks workspace has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Databricks workspace does not have diagnostic logs enabled', function (done) {
            const cache = createCache([workspaces[0]],[diagnosticSettings[1]] );
            workspaceDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Databricks workspace does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});