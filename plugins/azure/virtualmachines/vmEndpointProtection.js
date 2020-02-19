var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Endpoint Protection',
    category: 'Virtual Machines',
    description: 'Ensures that VM Endpoint Protection is enabled for all virtual machines',
    more_info: 'Installing endpoint protection systems provides for real-time protection capabilities that help identify and remove viruses, spyware, and other malicious software, with configurable alerts for malicious or unwanted software.',
    recommended_action: 'Install endpoint protection on all virtual machines.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-install-endpoint-protection',
    apis: ['resourceGroups:list', 'virtualMachines:listAll', 'virtualMachineExtensions:list'],
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

            var virtualMachines = helpers.addSource(cache, source, ['virtualMachines', 'listAll', location]);

            var VMs = [];

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
            } else {
                for(i in virtualMachines.data){
                    if (virtualMachines.data[i]) {
                        VMs.push({
                            'vmId': (virtualMachines.data[i].id ? virtualMachines.data[i].id : 'VM Id Not Found'),
                            'vmName': (virtualMachines.data[i].name ? virtualMachines.data[i].name : 'VM Name Not Found'),
                            'protected': false
                        });
                    }
                }

                var virtualMachineExtensions = helpers.addSource(cache, source, ['virtualMachineExtensions', 'list', location]);

                var IaaSAntimalware = [];

                if (!virtualMachineExtensions) return rcb();

                if (virtualMachineExtensions.err || !virtualMachineExtensions.data) {
                    helpers.addResult(results, 3, 'Unable to query for VM Extensions: ' + helpers.addError(virtualMachineExtensions), location);
                    return rcb();
                }
                if (!virtualMachineExtensions.data.length) {
                    helpers.addResult(results, 2, 'No VM Extensions found', location);
                } else {
                    for(var vm in virtualMachineExtensions.data){
                        if (virtualMachineExtensions.data[vm]) {
                            var virtualMachine = virtualMachineExtensions.data[vm];
                            for(var ext in virtualMachine.value) {
                                var extension = virtualMachine.value[ext];
                                if (extension.name &&
                                    extension.name.search("IaaSAntimalware") > -1
                                ) {
                                    IaaSAntimalware.push({
                                        'extId': (extension.id ? extension.id : 'Ext Id Not Found'),
                                        'extName': (extension.name ? extension.name : 'Ext Name Not Found'),
                                        'extSettings':(extension.settings && extension.settings.AntimalwareEnabled ? extension.settings.AntimalwareEnabled : 'Ext Settings Not Found'),
                                        'extVM': (extension.id && extension.id.split("/").length>7 ? extension.id.split("/")[8] : 'Could not read extVM'),
                                    });
                                }
                            }
                        }
                    }
                }

                for(i in VMs){
                    for(j in IaaSAntimalware){
                        if(VMs[i].vmName === IaaSAntimalware[j].extVM
                            && IaaSAntimalware[j].extSettings == 'true') {
                            VMs[i].protected = true;
                        }
                    }
                }

                var reg = 0;
                for(i in VMs){
                    if(!VMs[i].protected){
                        helpers.addResult(results, 2, 'Endpoint protection is not installed on this virtual machine', location, VMs[i].vmId);
                        reg++;
                    }
                }

                if(!reg){
                    helpers.addResult(results, 0, 'Endpoint protection is installed on all virtual machines', location);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source)
        });
    }
};