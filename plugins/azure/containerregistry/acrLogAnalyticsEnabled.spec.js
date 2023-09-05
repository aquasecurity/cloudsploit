var expect = require('chai').expect;
var acrLogAnalyticsEnabled = require('./acrLogAnalyticsEnabled');

const containerRegistries = [
   {
        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.ContainerRegistry/registries/testregistry12543",
        "name": "testregistry12543",
        "type": "Microsoft.ContainerRegistry/registries",
        "location": "eastus",
        "tags": {},
        "sku": {
            "name": "Basic",
            "tier": "Basic"
        },
        "loginServer": "testregistry12543.azurecr.io",
        "creationDate": "2019-10-18T21:16:01.347Z",
        "provisioningState": "Succeeded",
        "adminUserEnabled": true,
        "publicNetworkAccess": "Enabled"
    }
];

const diagnosticSettings = [
  {
    id: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/devresourcegroup/providers/Microsoft.ContainerRegistry/registries/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting',
    type: 'Microsoft.Insights/diagnosticSettings',
    name: 'gio-test-setting',
    location: 'eastus',
    kind: null,
    tags: null,
    identity: null,
    storageAccountId: null,
    serviceBusRuleId: null,
    workspaceId: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/defaultresourcegroup-eus/providers/microsoft.operationalinsights/workspaces/defaultworkspace-dce7d0ad-ebf6-437f-a3b0-28fc0d22117e-eus',
    eventHubAuthorizationRuleId: null,
    eventHubName: null,
    metrics: [],
    logs: [
      {
        category: 'NetworkSecurityGroupEvent',
        categoryGroup: null,
        enabled: true,
        retentionPolicy: [Object]
      },
      {
        category: 'NetworkSecurityGroupRuleCounter',
        categoryGroup: null,
        enabled: true,
        retentionPolicy: [Object]
      }
    ],
    logAnalyticsDestinationType: null
  },
  {
    id: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting',
    type: 'Microsoft.Insights/diagnosticSettings',
    name: 'gio-test-setting',
    location: 'eastus',
    kind: null,
    tags: null,
    identity: null,
    storageAccountId: null,
    serviceBusRuleId: null,
    workspaceId: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/defaultresourcegroup-eus/providers/microsoft.operationalinsights/workspaces/defaultworkspace-dce7d0ad-ebf6-437f-a3b0-28fc0d22117e-eus',
    eventHubAuthorizationRuleId: null,
    eventHubName: null,
    metrics: [],
    logs: [],
    logAnalyticsDestinationType: null
  }
];


const createCache = (listRegistries, diagnosticSetting) => {
    let logs = {};
    if (listRegistries && listRegistries.length > 0) {
        logs[listRegistries[0].id] = {
            data: diagnosticSetting
        };
    }

    return {
        registries: {
            list: {
                'eastus': {
                    data: listRegistries
                }
            }
        },
        diagnosticSettings: {
          listByContainerRegistries: {
                'eastus': logs
            }
        }
    };
};

describe('acrLogAnalyticsEnabled', function() {
    describe('run', function() {
        it('should give passing result if No existing container registry found', function(done) {
            const cache = createCache([], []);
            acrLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing container registries found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give Failing result if No existing diagnostics settings', function(done) {
            const cache = createCache([containerRegistries[0]],[]);
            acrLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing diagnostics settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for container registry Groups', function(done) {
            const cache = createCache(null);
            acrLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for container registries:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Log Analytics is enabled for ACR', function(done) {
            const cache = createCache([containerRegistries[0]], [diagnosticSettings[0]]);
            acrLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Logging is enabled for container registry');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Log Analytics is not enabled for ACR', function(done) {
            const cache = createCache([containerRegistries[0]], [diagnosticSettings[1]]);
            acrLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Logging is not enabled for container registry');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});