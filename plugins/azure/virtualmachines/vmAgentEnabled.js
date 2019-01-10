var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Agent Enabled',
    category: 'Virtual Machines',
    description: 'Ensure that the VM Agent is enabled',
    more_info: 'The VM agent must be enabled on Azure virtual machines (VMs) in order to enable Azure Security center for data collection',
    recommended_action: 'Enable the VM agent for all virtual machines',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-vm-agent',
    apis: ['virtualMachines:listAll'],

    run: function(cache, settings, callback) {
		var results = [];
		var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb){

            var virtualMachines = helpers.addSource(cache, source, ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

			if (virtualMachines.err || !virtualMachines.data) {
				helpers.addResult(results, 3, 'Unable to query Virtual Machines: ' + helpers.addError(virtualMachines), location);
				return rcb();
            }
            if (!virtualMachines.data.length) {
				helpers.addResult(results, 0, 'No existing virtual machines', location);
			} else {
                var reg = 0;
                for(i in virtualMachines.data){
                    var VMConfig = Object.keys(virtualMachines.data[i].osProfile)[2];
                    if(virtualMachines.data[i].osProfile && !virtualMachines.data[i].osProfile[VMConfig].provisionVMAgent){
                        helpers.addResult(results, 2, 'VM agent is not enabled for this VM '+virtualMachines.data[i].name, location, virtualMachines.data[i].id);
                        reg++;
                    } 
                }
                if(!reg){
                    helpers.addResult(results, 0, 'VM agent is enabled', location);
                }
                
            }
            rcb();
        }, function(){
			// Global checking goes here
            callback(null, results, source);
        });
    }
}