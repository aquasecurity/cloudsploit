var expect = require('chai').expect;
var lbLogAnalyticsEnabled = require('./lbLogAnalyticsEnabled');

const loadBalancers = [
    {
        "name": "kubernetes",
        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes",
        "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
        "type": "Microsoft.Network/loadBalancers",
        "location": "eastus",
        "sku": {
          "name": "Standard"
        },
        "provisioningState": "Succeeded",
        "resourceGuid": "e88ed351-f991-4268-94f5-57334c1443af",
        "frontendIPConfigurations": [
          {
            "name": "3859f556-a02d-42d9-8bd3-42301f41f8be",
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/frontendIPConfigurations/3859f556-a02d-42d9-8bd3-42301f41f8be",
            "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
            "type": "Microsoft.Network/loadBalancers/frontendIPConfigurations",
            "properties": {
              "provisioningState": "Succeeded",
              "privateIPAllocationMethod": "Dynamic",
              "publicIPAddress": {
                "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/publicIPAddresses/3859f556-a02d-42d9-8bd3-42301f41f8be"
              },
              "inboundNatRules": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/inboundNatRules/jbs"
                }
              ],
              "outboundRules": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/outboundRules/aksOutboundRule"
                }
              ]
            }
          }
        ],
        "backendAddressPools": [
          {
            "name": "aksOutboundBackendPool",
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/backendAddressPools/aksOutboundBackendPool",
            "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
            "properties": {
              "provisioningState": "Succeeded",
              "outboundRules": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/outboundRules/aksOutboundRule"
                }
              ],
              "backendIPConfigurations": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Compute/virtualMachineScaleSets/aks-agentpool-30757528-vmss/virtualMachines/1/networkInterfaces/aks-agentpool-30757528-vmss/ipConfigurations/ipconfig1"
                }
              ]
            },
            "type": "Microsoft.Network/loadBalancers/backendAddressPools"
          },
          {
            "name": "kubernetes",
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/backendAddressPools/kubernetes",
            "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
            "properties": {
              "provisioningState": "Succeeded",
              "backendIPConfigurations": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Compute/virtualMachineScaleSets/aks-agentpool-30757528-vmss/virtualMachines/1/networkInterfaces/aks-agentpool-30757528-vmss/ipConfigurations/ipconfig1"
                }
              ]
            },
            "type": "Microsoft.Network/loadBalancers/backendAddressPools"
          }
        ],
        "loadBalancingRules": [],
        "probes": [],
        "inboundNatRules": [
          {
            "name": "jbs",
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/inboundNatRules/jbs",
            "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
            "type": "Microsoft.Network/loadBalancers/inboundNatRules",
            "properties": {
              "provisioningState": "Succeeded",
              "frontendIPConfiguration": {
                "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/frontendIPConfigurations/3859f556-a02d-42d9-8bd3-42301f41f8be"
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
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/outboundRules/aksOutboundRule",
            "etag": "W/\"b44d8556-daee-4b29-b12f-f6b140df6cbd\"",
            "type": "Microsoft.Network/loadBalancers/outboundRules",
            "properties": {
              "provisioningState": "Succeeded",
              "allocatedOutboundPorts": 0,
              "protocol": "All",
              "enableTcpReset": true,
              "idleTimeoutInMinutes": 30,
              "backendAddressPool": {
                "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/backendAddressPools/aksOutboundBackendPool"
              },
              "frontendIPConfigurations": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/frontendIPConfigurations/3859f556-a02d-42d9-8bd3-42301f41f8be"
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
        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/mc_ali-resource-group_test-ali_eastus/providers/microsoft.network/loadbalancers/kubernetes/providers/microsoft.insights/diagnosticSettings/monitor-lb",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "monitor-lb",
        "location": "eastus",
        "kind": null,
        "tags": null,
        "identity": null,
        "storageAccountId": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/akhtar-rg/providers/Microsoft.Storage/storageAccounts/akhtarrgdiag",
        "serviceBusRuleId": null,
        "workspaceId": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/defaultresourcegroup-eus/providers/microsoft.operationalinsights/workspaces/defaultworkspace-dce7d0ad-ebf6-437f-a3b0-28fc0d22117e-eus",
        "eventHubAuthorizationRuleId": null,
        "eventHubName": null,
        "metrics": [
          {
            "category": "AllMetrics",
            "enabled": true,
            "retentionPolicy": {
              "enabled": true,
              "days": 7
            }
          }
        ],
        "logs": [
          {
            "category": "LoadBalancerAlertEvent",
            "categoryGroup": null,
            "enabled": false,
            "retentionPolicy": {
              "enabled": false,
              "days": 0
            }
          },
          {
            "category": "LoadBalancerProbeHealthStatus",
            "categoryGroup": null,
            "enabled": false,
            "retentionPolicy": {
              "enabled": false,
              "days": 0
            }
          }
        ],
        "logAnalyticsDestinationType": null
    },
    {
        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/mc_ali-resource-group_test-ali_eastus/providers/microsoft.network/loadbalancers/kubernetes/providers/microsoft.insights/diagnosticSettings/monitor-lb",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "monitor-lb",
        "location": "eastus",
        "kind": null,
        "tags": null,
        "identity": null,
        "storageAccountId": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/akhtar-rg/providers/Microsoft.Storage/storageAccounts/akhtarrgdiag",
        "serviceBusRuleId": null,
        "workspaceId": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/defaultresourcegroup-eus/providers/microsoft.operationalinsights/workspaces/defaultworkspace-dce7d0ad-ebf6-437f-a3b0-28fc0d22117e-eus",
        "eventHubAuthorizationRuleId": null,
        "eventHubName": null,
        "metrics": [
          {
            "category": "AllMetrics",
            "enabled": true,
            "retentionPolicy": {
              "enabled": true,
              "days": 7
            }
          }
        ],
        "logs": [],
        "logAnalyticsDestinationType": null
    }
];


const createCache = (loadBalancer, diagnosticSetting) => {
    let logs = {};
    if (loadBalancer.length > 0) {
        logs[loadBalancer[0].id] = {
            data: diagnosticSetting
        };
    }

    return {
        loadBalancers: {
            listAll: {
                'eastus': {
                    data: loadBalancer
                }
            }
        },
        diagnosticSettings: {
            listByLoadBalancer: {
                'eastus': logs
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key === 'loadbalancer') {
        return {
            loadBalancers: {
                listAll: {
                    'eastus': {}
                }
            }
        };
    } else {
        return {
            loadBalancers: {
                listAll: {
                    'eastus': {
                        data: [loadBalancers[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByLoadBalancer: {
                    'eastus': {}
                }
            }
        };
    }
};

describe('lbLogAnalyticsEnabled', function() {
    describe('run', function() {
        it('should give passing result if No existing Load Balancers found', function(done) {
            const cache = createCache([], []);
            lbLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Load Balancers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give Failing result if No existing diagnostics settings', function(done) {
            const cache = createCache([loadBalancers[0]],[]);
            lbLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing diagnostics settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Load Balancers', function(done) {
            const cache = createErrorCache('loadbalancer');
            lbLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Load Balancers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query diagnostics settings', function(done) {
            const cache = createErrorCache('flowLog');
            lbLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query diagnostics settings:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Log analytics is enabled for load balancer', function(done) {
            const cache = createCache([loadBalancers[0]], [diagnosticSettings[0]]);
            lbLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Log analytics is enabled for load balancer');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Log analytics is not enabled for load balancer', function(done) {
            const cache = createCache([loadBalancers[0]], [diagnosticSettings[1]]);
            lbLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Log analytics is not enabled for load balancer');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});