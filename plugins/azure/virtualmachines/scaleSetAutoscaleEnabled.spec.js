var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./scaleSetAutoscaleEnabled');

const createCache = (err, list, get) => {
    return {
        virtualMachineScaleSets: {
            listAll: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        },
        autoscaleSettings: {
            listBySubscription: {
                'eastus': {
                    err: err,
                    data: get
                }
            }
        }
    }
};

describe('scaleSetAutoscaleEnabled', function() {
    describe('run', function() {
        it('should give unknown result if a scale set error is passed or no data is present', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
                {}
            );

            plugin.run(cache, {}, callback);
        })
        it('should give unknown result if an autoscale error is passed or no data is present', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for AutoScale settings')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                ['data'],
                 null,
                {}
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no scale set records are found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [],
                {}
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if all scale sets have Autoscale Enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Virtual Machine Scale Set has autoscale enabled')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Compute/virtualMachineScaleSets/gioScaleSet1",
                        "name": "gioScaleSet1",
                        "type": "Microsoft.Compute/virtualMachineScaleSets",
                        "location": "eastus",
                        "provisioningState": "Succeeded",
                        "overprovision": true,
                        "uniqueId": "866a138f-93d7-4d0d-89b4-c25762373a58",
                        "singlePlacementGroup": false,
                        "platformFaultDomainCount": 1,
                        "zones": [
                            "1"
                        ],
                        "storageAccount": {
                            "name": "Default-ActivityLogAlerts"
                        }
                    }
                ],
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/microsoft.insights/autoscalesettings/ASP-devresourcegroup-b56f-Autoscale-931",
                        "name": "ASP-devresourcegroup-b56f-Autoscale-931",
                        "type": "Microsoft.Insights/autoscaleSettings",
                        "location": "eastus",
                        "tags": {
                            "$type": "Microsoft.WindowsAzure.Management.Common.Storage.CasePreservedDictionary, Microsoft.WindowsAzure.Management.Common.Storage"
                        },
                        "profiles": [
                            {
                                "name": "Auto created scale condition 1",
                                "capacity": {
                                    "minimum": "1",
                                    "maximum": "2",
                                    "default": "1"
                                },
                                "rules": [
                                    {
                                        "metricTrigger": {
                                            "metricName": "CpuPercentage",
                                            "metricResourceUri": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.Web/serverFarms/ASP-devresourcegroup-b56f",
                                            "timeGrain": "PT1M",
                                            "statistic": "Average",
                                            "timeWindow": "PT10M",
                                            "timeAggregation": "Average",
                                            "operator": "GreaterThan",
                                            "threshold": 70
                                        },
                                        "scaleAction": {
                                            "direction": "Increase",
                                            "type": "ChangeCount",
                                            "value": "1",
                                            "cooldown": "PT5M"
                                        }
                                    }
                                ],
                                "fixedDate": {
                                    "timeZone": "Pacific Standard Time",
                                    "start": "2019-06-08T00:00:00.000Z",
                                    "end": "2019-06-08T23:59:00.000Z"
                                }
                            },
                            {
                                "name": "Auto created scale condition",
                                "capacity": {
                                    "minimum": "1",
                                    "maximum": "1",
                                    "default": "1"
                                },
                                "rules": []
                            }
                        ],
                        "notifications": [
                            {
                                "operation": "Scale",
                                "email": {
                                    "sendToSubscriptionAdministrator": false,
                                    "sendToSubscriptionCoAdministrators": false,
                                    "customEmails": []
                                },
                                "webhooks": []
                            }
                        ],
                        "enabled": true,
                        "autoscaleSettingResourceName": "ASP-devresourcegroup-b56f-Autoscale-931",
                        "targetResourceUri": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Compute/virtualMachineScaleSets/gioScaleSet1",
                        "storageAccount": {
                            "name": "Default-ActivityLogAlerts"
                        }
                    },
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/dev2vnresourcegroup/providers/microsoft.insights/autoscalesettings/cpuautoscaleaztest1tp",
                        "name": "cpuautoscaleaztest1tp",
                        "type": "Microsoft.Insights/autoscaleSettings",
                        "location": "eastus",
                        "tags": {
                            "$type": "Microsoft.WindowsAzure.Management.Common.Storage.CasePreservedDictionary, Microsoft.WindowsAzure.Management.Common.Storage"
                        },
                        "profiles": [
                            {
                                "name": "Profile1",
                                "capacity": {
                                    "minimum": "1",
                                    "maximum": "10",
                                    "default": "1"
                                },
                                "rules": [
                                    {
                                        "metricTrigger": {
                                            "metricName": "Percentage CPU",
                                            "metricResourceUri": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/dev2vnresourcegroup/providers/Microsoft.Compute/virtualMachineScaleSets/aztest1",
                                            "timeGrain": "PT1M",
                                            "statistic": "Average",
                                            "timeWindow": "PT5M",
                                            "timeAggregation": "Average",
                                            "operator": "GreaterThan",
                                            "threshold": 75
                                        },
                                        "scaleAction": {
                                            "direction": "Increase",
                                            "type": "ChangeCount",
                                            "value": "1",
                                            "cooldown": "PT1M"
                                        }
                                    },
                                    {
                                        "metricTrigger": {
                                            "metricName": "Percentage CPU",
                                            "metricResourceUri": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/dev2vnresourcegroup/providers/Microsoft.Compute/virtualMachineScaleSets/aztest1",
                                            "timeGrain": "PT1M",
                                            "statistic": "Average",
                                            "timeWindow": "PT5M",
                                            "timeAggregation": "Average",
                                            "operator": "LessThan",
                                            "threshold": 25
                                        },
                                        "scaleAction": {
                                            "direction": "Decrease",
                                            "type": "ChangeCount",
                                            "value": "1",
                                            "cooldown": "PT1M"
                                        }
                                    }
                                ]
                            }
                        ],
                        "enabled": true,
                        "autoscaleSettingResourceName": "cpuautoscaleaztest1tp",
                        "targetResourceUri": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/dev2vnresourcegroup/providers/Microsoft.Compute/virtualMachineScaleSets/aztest1",
                        "storageAccount": {
                            "name": "dev2vnresourcegroup"
                        }
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if the scale set has Autoscale Disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Virtual Machine Scale Set does not have autoscale enabled')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Compute/virtualMachineScaleSets/gioScaleSet1",
                        "name": "gioScaleSet1",
                        "type": "Microsoft.Compute/virtualMachineScaleSets",
                        "location": "eastus",
                        "sku": {
                            "name": "Standard_DS1_v2",
                            "tier": "Standard",
                            "capacity": 2
                        },
                        "upgradePolicy": {
                            "mode": "Manual"
                        },
                        "virtualMachineProfile": {
                            "osProfile": {
                                "computerNamePrefix": "gioscales",
                                "adminUsername": "Gio",
                                "windowsConfiguration": {
                                    "provisionVMAgent": true,
                                    "enableAutomaticUpdates": true
                                },
                                "secrets": []
                            },
                            "storageProfile": {
                                "imageReference": {
                                    "publisher": "MicrosoftWindowsServer",
                                    "offer": "WindowsServer",
                                    "sku": "2016-Datacenter",
                                    "version": "latest"
                                },
                                "osDisk": {
                                    "caching": "ReadWrite",
                                    "createOption": "FromImage",
                                    "managedDisk": {
                                        "storageAccountType": "Premium_LRS"
                                    }
                                }
                            },
                            "networkProfile": {
                                "networkInterfaceConfigurations": [
                                    {
                                        "name": "gioScaleSet1Nic",
                                        "primary": true,
                                        "enableAcceleratedNetworking": false,
                                        "dnsSettings": {
                                            "dnsServers": []
                                        },
                                        "ipConfigurations": [
                                            {
                                                "name": "gioScaleSet1IpConfig",
                                                "subnet": {
                                                    "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Network/virtualNetworks/gioVNtest1/subnets/subnettest1"
                                                },
                                                "privateIPAddressVersion": "IPv4"
                                            }
                                        ],
                                        "enableIPForwarding": false
                                    }
                                ]
                            },
                            "priority": "Regular"
                        },
                        "provisioningState": "Succeeded",
                        "overprovision": true,
                        "uniqueId": "866a138f-93d7-4d0d-89b4-c25762373a58",
                        "singlePlacementGroup": false,
                        "platformFaultDomainCount": 1,
                        "zones": [
                            "1"
                        ],
                        "storageAccount": {
                            "name": "Default-ActivityLogAlerts"
                        }
                    }
                ],
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/microsoft.insights/autoscalesettings/ASP-devresourcegroup-b56f-Autoscale-931",
                        "name": "ASP-devresourcegroup-b56f-Autoscale-931",
                        "type": "Microsoft.Insights/autoscaleSettings",
                        "location": "eastus",
                        "tags": {
                            "$type": "Microsoft.WindowsAzure.Management.Common.Storage.CasePreservedDictionary, Microsoft.WindowsAzure.Management.Common.Storage"
                        },
                        "profiles": [
                            {
                                "name": "Auto created scale condition 1",
                                "capacity": {
                                    "minimum": "1",
                                    "maximum": "2",
                                    "default": "1"
                                },
                                "rules": [
                                    {
                                        "metricTrigger": {
                                            "metricName": "CpuPercentage",
                                            "metricResourceUri": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.Web/serverFarms/ASP-devresourcegroup-b56f",
                                            "timeGrain": "PT1M",
                                            "statistic": "Average",
                                            "timeWindow": "PT10M",
                                            "timeAggregation": "Average",
                                            "operator": "GreaterThan",
                                            "threshold": 70
                                        },
                                        "scaleAction": {
                                            "direction": "Increase",
                                            "type": "ChangeCount",
                                            "value": "1",
                                            "cooldown": "PT5M"
                                        }
                                    }
                                ],
                                "fixedDate": {
                                    "timeZone": "Pacific Standard Time",
                                    "start": "2019-06-08T00:00:00.000Z",
                                    "end": "2019-06-08T23:59:00.000Z"
                                }
                            },
                            {
                                "name": "Auto created scale condition",
                                "capacity": {
                                    "minimum": "1",
                                    "maximum": "1",
                                    "default": "1"
                                },
                                "rules": []
                            }
                        ],
                        "notifications": [
                            {
                                "operation": "Scale",
                                "email": {
                                    "sendToSubscriptionAdministrator": false,
                                    "sendToSubscriptionCoAdministrators": false,
                                    "customEmails": []
                                },
                                "webhooks": []
                            }
                        ],
                        "enabled": false,
                        "autoscaleSettingResourceName": "ASP-devresourcegroup-b56f-Autoscale-931",
                        "targetResourceUri": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.Web/serverFarms/ASP-devresourcegroup-b56f",
                        "storageAccount": {
                            "name": "Default-ActivityLogAlerts"
                        }
                    },
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/dev2vnresourcegroup/providers/microsoft.insights/autoscalesettings/cpuautoscaleaztest1tp",
                        "name": "cpuautoscaleaztest1tp",
                        "type": "Microsoft.Insights/autoscaleSettings",
                        "location": "eastus",
                        "tags": {
                            "$type": "Microsoft.WindowsAzure.Management.Common.Storage.CasePreservedDictionary, Microsoft.WindowsAzure.Management.Common.Storage"
                        },
                        "profiles": [
                            {
                                "name": "Profile1",
                                "capacity": {
                                    "minimum": "1",
                                    "maximum": "10",
                                    "default": "1"
                                },
                                "rules": [
                                    {
                                        "metricTrigger": {
                                            "metricName": "Percentage CPU",
                                            "metricResourceUri": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/dev2vnresourcegroup/providers/Microsoft.Compute/virtualMachineScaleSets/aztest1",
                                            "timeGrain": "PT1M",
                                            "statistic": "Average",
                                            "timeWindow": "PT5M",
                                            "timeAggregation": "Average",
                                            "operator": "GreaterThan",
                                            "threshold": 75
                                        },
                                        "scaleAction": {
                                            "direction": "Increase",
                                            "type": "ChangeCount",
                                            "value": "1",
                                            "cooldown": "PT1M"
                                        }
                                    },
                                    {
                                        "metricTrigger": {
                                            "metricName": "Percentage CPU",
                                            "metricResourceUri": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/dev2vnresourcegroup/providers/Microsoft.Compute/virtualMachineScaleSets/aztest1",
                                            "timeGrain": "PT1M",
                                            "statistic": "Average",
                                            "timeWindow": "PT5M",
                                            "timeAggregation": "Average",
                                            "operator": "LessThan",
                                            "threshold": 25
                                        },
                                        "scaleAction": {
                                            "direction": "Decrease",
                                            "type": "ChangeCount",
                                            "value": "1",
                                            "cooldown": "PT1M"
                                        }
                                    }
                                ]
                            }
                        ],
                        "enabled": false,
                        "autoscaleSettingResourceName": "cpuautoscaleaztest1tp",
                        "targetResourceUri": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/dev2vnresourcegroup/providers/Microsoft.Compute/virtualMachineScaleSets/aztest1",
                        "storageAccount": {
                            "name": "dev2vnresourcegroup"
                        }
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })
    })
})