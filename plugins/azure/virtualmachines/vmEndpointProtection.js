var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Endpoint Protection',
    category: 'Virtual Machines',
    description: 'Ensure that the VM Endpoint Protection is installed for all VMs',
    more_info: 'Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software, with configurable alerts when known malicious or unwanted software attempts to install itself or run on your Azure systems',
    recommended_action: 'Install endpoint protection on your Azure systems',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-install-endpoint-protection',
    apis: ['resourceGroups:list', 'virtualMachines:listAll', 'virtualMachineExtensions:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb){

            var virtualMachines = helpers.addSource(cache, source, ['virtualMachines', 'listAll', location]);

            var VMs = [];

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
				helpers.addResult(results, 3, 'Unable to query Virtual Machines: ' + helpers.addError(virtualMachines), location);
				return rcb();
            }

            if (!virtualMachines.data.length) {
				helpers.addResult(results, 0, 'No existing Virtual Machines', location);
			} else {
                for(i in virtualMachines.data){
                    VMs.push({
                        'vmId': virtualMachines.data[i].id,
                        'vmName': virtualMachines.data[i].name,
                        'protected': false
                    });
                }

                var virtualMachineExtensions = helpers.addSource(cache, source, ['virtualMachineExtensions', 'list', location]);

                var IaaSAntimalware = [];

                if (!virtualMachineExtensions) return rcb();

                if (virtualMachineExtensions.err || !virtualMachineExtensions.data) {
                    helpers.addResult(results, 3, 'Unable to query VM Extensions: ' + helpers.addError(virtualMachineExtensions), location);
                    return rcb();
                }
                if (!virtualMachineExtensions.data.length) {
                    helpers.addResult(results, 1, 'No existing VM Extensions', location);
                } else {
                    for(var vm in virtualMachineExtensions.data){
                        var virtualMachine = virtualMachineExtensions.data[vm];
                        for(var ext in virtualMachine.value) {
                            var extension = virtualMachine.value[ext];
                            if (extension.name &&
                                extension.name.search("IaaSAntimalware") > -1) {
                                IaaSAntimalware.push({
                                    'extId': extension.id,
                                    'extName': extension.name,
                                    'extSettings': extension.settings.AntimalwareEnabled,
                                    'extVM': extension.id.split("/")[8]
                                });
                            }
                        }
                    }
                }

                for(i in VMs){
                    for(j in IaaSAntimalware){
                        if(VMs[i].vmName === IaaSAntimalware[j].extVM && IaaSAntimalware[j].extSettings == 'true'){
                            VMs[i].protected = true;
                        }
                    }
                }

                var reg = 0;
                for(i in VMs){
                    if(!VMs[i].protected){
                        helpers.addResult(results, 2, 'Endpoint protection is not installed on this VM', location, VMs[i].vmId);
                        reg++;
                    }
                }

                if(!reg){
                    helpers.addResult(results, 0, 'Endpoint protection is installed', location);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source)
        });
    }
};