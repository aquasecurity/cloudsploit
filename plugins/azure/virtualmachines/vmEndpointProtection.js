var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Endpoint Protection',
    category: 'Virtual Machines',
    description: 'Ensures that VM Endpoint Protection is enabled for all virtual machines',
    more_info: 'Installing endpoint protection systems provides for real-time protection capabilities that help identify and remove viruses, spyware, and other malicious software, with configurable alerts for malicious or unwanted software.',
    recommended_action: 'Install endpoint protection on all virtual machines.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-install-endpoint-protection',
    apis: ['virtualMachines:listAll', 'virtualMachineExtensions:list'],
    compliance: {
        pci: 'PCI requires the use of anti-virus and anti-malware solutions. Enabling ' +
                'VM endpoint protection provides real-time VM monitoring for malicious activity.',
        hipaa: 'HIPAA requires protection of all network systems, including monitoring ' +
                'all network traffic for malicious, inappropriate or unusual traffic.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb){
            var virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No Virtual Machines found', location);
            } else {
                virtualMachines.data.forEach(function(virtualMachine){
                    var windowsImg = false;
                    if (virtualMachine.storageProfile &&
                        virtualMachine.storageProfile.imageReference &&
                        virtualMachine.storageProfile.imageReference.offer &&
                        virtualMachine.storageProfile.imageReference.offer.toLowerCase().indexOf('windowsserver') > -1) {
                        windowsImg = true;
                    } else if (virtualMachine.storageProfile &&
                        virtualMachine.storageProfile.osDisk &&
                        virtualMachine.storageProfile.osDisk.osType &&
                        virtualMachine.storageProfile.osDisk.osType.toLowerCase().indexOf('windows') > -1) {
                        windowsImg = true;
                    }

                    var virtualMachineExtensions = helpers.addSource(cache, source,
                        ['virtualMachineExtensions', 'list', location, virtualMachine.id]);

                    if (!virtualMachineExtensions || virtualMachineExtensions.err || !virtualMachineExtensions.data) {
                        helpers.addResult(results, 3, 'Unable to query for VM Extensions: ' + helpers.addError(virtualMachineExtensions), location, virtualMachine.id);
                    } else if (!virtualMachineExtensions.data.length) {
                        if (!windowsImg) {
                            helpers.addResult(results, 2, 'No VM Extensions found', location, virtualMachine.id);
                        } else {
                            helpers.addResult(results, 0, 'The Microsoft VM does not offer endpoint protection', location, virtualMachine.id);
                        }
                    } else {
                        var antiMalware = false;
                        virtualMachineExtensions.data.forEach(function(virtualMachineExtension) {
                            if (virtualMachineExtension.type &&
                                virtualMachineExtension.type == 'IaaSAntimalware' &&
                                virtualMachineExtension.settings &&
                                virtualMachineExtension.settings.AntimalwareEnabled &&
                                virtualMachineExtension.settings.AntimalwareEnabled) {
                                antiMalware = true;
                            }
                        });

                        if (antiMalware) {
                            helpers.addResult(results, 0, 'Endpoint protection is installed on the virtual machine', location, virtualMachine.id);
                        } else {
                            if (!windowsImg) {
                                helpers.addResult(results, 2, 'Endpoint protection is not installed on the virtual machine', location, virtualMachine.id);
                            } else {
                                helpers.addResult(results, 0, 'The Microsoft VM does not offer endpoint protection', location, virtualMachine.id);
                            }
                        }
                    }
                });
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
