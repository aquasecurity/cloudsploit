var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./scaleSetMultiAz');

const createCache = (err, data) => {
    return {
        virtualMachineScaleSets: {
            listAll: {
                'eastus': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('scaleSetMultiAz', function() {
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
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if the scale set is multi Az', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('The Virtual Machine Scale Set is in multiple zone')
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
                            "1",
                            "2"
                        ],
                        "storageAccount": {
                            "name": "Default-ActivityLogAlerts"
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if the scale set is not multi Az', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('The Virtual Machine Scale Set is not in multiple zones')
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
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})