var expect = require('chai').expect;
var nsgLogAnalyticsEnabled = require('./nsgLogAnalyticsEnabled');

const networkSecurityGroups = [
    {
        "name": "kubernetes",
        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting",
        "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "sku": {
          "name": "Standard"
        },
        "provisioningState": "Succeeded",
        "resourceGuid": "e88ed351-f991-4268-94f5-57334c1443af",
        "frontendIPConfigurations": [
          {
            "name": "3859f556-a02d-42d9-8bd3-42301f41f8be",
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/frontendIPConfigurations/3859f556-a02d-42d9-8bd3-42301f41f8be",
            "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
            "type": "Microsoft.Network/networkSecurityGroups/frontendIPConfigurations",
            "properties": {
              "provisioningState": "Succeeded",
              "privateIPAllocationMethod": "Dynamic",
              "publicIPAddress": {
                "id": "/subscriptions/1234/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/publicIPAddresses/3859f556-a02d-42d9-8bd3-42301f41f8be"
              },
              "inboundNatRules": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/inboundNatRules/jbs"
                }
              ],
              "outboundRules": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/outboundRules/aksOutboundRule"
                }
              ]
            }
          }
        ],
        "backendAddressPools": [
          {
            "name": "aksOutboundBackendPool",
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/backendAddressPools/aksOutboundBackendPool",
            "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
            "properties": {
              "provisioningState": "Succeeded",
              "outboundRules": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/outboundRules/aksOutboundRule"
                }
              ],
              "backendIPConfigurations": [
                {
                  "id": "/subscriptions/1234/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Compute/virtualMachineScaleSets/aks-agentpool-30757528-vmss/virtualMachines/1/networkInterfaces/aks-agentpool-30757528-vmss/ipConfigurations/ipconfig1"
                }
              ]
            },
            "type": "Microsoft.Network/networkSecurityGroups/backendAddressPools"
          },
          {
            "name": "kubernetes",
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/backendAddressPools/kubernetes",
            "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
            "properties": {
              "provisioningState": "Succeeded",
              "backendIPConfigurations": [
                {
                  "id": "/subscriptions/1234/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Compute/virtualMachineScaleSets/aks-agentpool-30757528-vmss/virtualMachines/1/networkInterfaces/aks-agentpool-30757528-vmss/ipConfigurations/ipconfig1"
                }
              ]
            },
            "type": "Microsoft.Network/networkSecurityGroups/backendAddressPools"
          }
        ],
        "loadBalancingRules": [],
        "probes": [],
        "inboundNatRules": [
          {
            "name": "jbs",
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/inboundNatRules/jbs",
            "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
            "type": "Microsoft.Network/networkSecurityGroups/inboundNatRules",
            "properties": {
              "provisioningState": "Succeeded",
              "frontendIPConfiguration": {
                "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/frontendIPConfigurations/3859f556-a02d-42d9-8bd3-42301f41f8be"
              },
              "frontendPort": 22,
              "backendPort": 22,
              "enableFloatingIP": false,
              "idleTimeoutInMinutes": 4,
              "protocol": "Tcp",
              "enableDestinationServiceEndpoint": false,
              "enableTcpReset": false,
              "allowBackendPortConflict": false
            }
          }
        ],
        "outboundRules": [
          {
            "name": "aksOutboundRule",
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/outboundRules/aksOutboundRule",
            "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
            "type": "Microsoft.Network/networkSecurityGroups/outboundRules",
            "properties": {
              "provisioningState": "Succeeded",
              "allocatedOutboundPorts": 0,
              "protocol": "All",
              "enableTcpReset": true,
              "idleTimeoutInMinutes": 30,
              "backendAddressPool": {
                "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/backendAddressPools/aksOutboundBackendPool"
              },
              "frontendIPConfigurations": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/deleteasap/providers/microsoft.network/networksecuritygroups/gio-test-events-1-nsg/providers/microsoft.insights/diagnosticSettings/gio-test-setting/frontendIPConfigurations/3859f556-a02d-42d9-8bd3-42301f41f8be"
                }
              ]
            }
          }
        ],
        "inboundNatPools": []
    }
];

const diagnosticSettings = [
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


const createCache = (networkSecurityGroup, diagnosticSetting) => {
    let logs = {};
    if (networkSecurityGroup.length > 0) {
        logs[networkSecurityGroup[0].id] = {
            data: diagnosticSetting
        };
    }

    return {
        networkSecurityGroups: {
            listAll: {
                'eastus': {
                    data: networkSecurityGroup
                }
            }
        },
        diagnosticSettings: {
          listByNetworkSecurityGroup: {
                'eastus': logs
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key === 'loadbalancer') {
        return {
            networkSecurityGroups: {
                listAll: {
                    'eastus': {}
                }
            }
        };
    } else {
        return {
            networkSecurityGroups: {
                listAll: {
                    'eastus': {
                        data: [networkSecurityGroups[0]]
                    }
                }
            },
            diagnosticSettings: {
              listByNetworkSecurityGroup: {
                    'eastus': {}
                }
            }
        };
    }
};

describe('nsgLogAnalyticsEnabled', function() {
    describe('run', function() {
        it('should give passing result if No existing Network Security Groups found', function(done) {
            const cache = createCache([], []);
            nsgLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Network Security Groups found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give Failing result if No existing diagnostics settings', function(done) {
            const cache = createCache([networkSecurityGroups[0]],[]);
            nsgLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing diagnostics settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Network Security Groups', function(done) {
            const cache = createErrorCache('loadbalancer');
            nsgLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Network Security Groups:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query diagnostics settings', function(done) {
            const cache = createErrorCache('flowLog');
            nsgLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query diagnostics settings:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if NSG Log Analytics is enabled for NSG', function(done) {
            const cache = createCache([networkSecurityGroups[0]], [diagnosticSettings[0]]);
            nsgLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('NSG Log Analytics is enabled for NSG');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if NSG Log Analytics is not enabled for NSG', function(done) {
            const cache = createCache([networkSecurityGroups[0]], [diagnosticSettings[1]]);
            nsgLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('NSG Log Analytics is not enabled for NSG');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});