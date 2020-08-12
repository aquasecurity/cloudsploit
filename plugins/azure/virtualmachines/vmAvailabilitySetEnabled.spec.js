var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./vmAvailabilitySetEnabled');

const createCache = (err, data) => {
    return {

        virtualMachines: {
            listAll: {
                'eastus': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('vmAvailabilitySetEnabled', function() {
    describe('run', function() {
        it('should give unknown result if a virtual machine error is passed or no data is present', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for Virtual Machines')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no virtual machine records are found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No existing Virtual Machines found')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if all virtual machines have availability sets enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('The Virtual Machine has Availability Set enabled')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/DEFAULT-ACTIVITYLOGALERTS/providers/Microsoft.Compute/virtualMachines/test1",
                        "name": "test1",
                        "type": "Microsoft.Compute/virtualMachines",
                        "location": "eastus",
                        "hardwareProfile": {
                            "vmSize": "Standard_D2s_v3"
                        },
                        "storageProfile": {
                            "imageReference": {
                                "publisher": "Canonical",
                                "offer": "UbuntuServer",
                                "sku": "18.04-LTS",
                                "version": "latest"
                            },
                            "osDisk": {
                                "osType": "Linux",
                                "name": "test1_OsDisk_1_e7fb8ef5859f4c63ae6549467739cb43",
                                "caching": "ReadWrite",
                                "createOption": "FromImage",
                                "diskSizeGB": 30,
                                "managedDisk": {
                                    "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Compute/disks/test1_OsDisk_1_e7fb8ef5859f4c63ae6549467739cb43",
                                    "storageAccountType": "Premium_LRS"
                                }
                            },
                            "dataDisks": []
                        },
                        "osProfile": {
                            "computerName": "test1",
                            "adminUsername": "gio",
                            "linuxConfiguration": {
                                "disablePasswordAuthentication": false,
                                "provisionVMAgent": true
                            },
                            "secrets": [],
                            "allowExtensionOperations": true
                        },
                        "networkProfile": {
                            "networkInterfaces": [
                                {
                                    "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Network/networkInterfaces/test1210"
                                }
                            ]
                        },
                        "diagnosticsProfile": {
                            "bootDiagnostics": {
                                "enabled": true,
                                "storageUri": "https://defaultactivitylogale920.blob.core.windows.net/"
                            }
                        },
                        "availabilitySet": {
                            "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/DEFAULT-ACTIVITYLOGALERTS/providers/Microsoft.Compute/availabilitySets/ASTEST1"
                        },
                        "provisioningState": "Succeeded",
                        "vmId": "9a2a3cb4-ebaa-4836-b16a-50e7496a8eaa"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if the virtual machine does not have availability sets enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('The Virtual Machine does not have Availability Set enabled')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/DEFAULT-ACTIVITYLOGALERTS/providers/Microsoft.Compute/virtualMachines/gioNoAS1",
                        "name": "gioNoAS1",
                        "type": "Microsoft.Compute/virtualMachines",
                        "location": "eastus",
                        "hardwareProfile": {
                            "vmSize": "Standard_D2s_v3"
                        },
                        "storageProfile": {
                            "imageReference": {
                                "publisher": "Canonical",
                                "offer": "UbuntuServer",
                                "sku": "18.04-LTS",
                                "version": "latest"
                            },
                            "osDisk": {
                                "osType": "Linux",
                                "name": "gioNoAS1_disk1_060a0d44fe0b4ded94bd6e6d63c33ab7",
                                "caching": "ReadWrite",
                                "createOption": "FromImage",
                                "diskSizeGB": 30,
                                "managedDisk": {
                                    "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Compute/disks/gioNoAS1_disk1_060a0d44fe0b4ded94bd6e6d63c33ab7",
                                    "storageAccountType": "Premium_LRS"
                                }
                            },
                            "dataDisks": []
                        },
                        "osProfile": {
                            "computerName": "gioNoAS1",
                            "adminUsername": "gio",
                            "linuxConfiguration": {
                                "disablePasswordAuthentication": false,
                                "provisionVMAgent": true
                            },
                            "secrets": [],
                            "allowExtensionOperations": true
                        },
                        "networkProfile": {
                            "networkInterfaces": [
                                {
                                    "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Network/networkInterfaces/gionoas182"
                                }
                            ]
                        },
                        "diagnosticsProfile": {
                            "bootDiagnostics": {
                                "enabled": true,
                                "storageUri": "https://defaultactivitylogale920.blob.core.windows.net/"
                            }
                        },
                        "provisioningState": "Succeeded",
                        "vmId": "6430e55b-f1c2-4b3e-a5b9-479433ab247d"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})