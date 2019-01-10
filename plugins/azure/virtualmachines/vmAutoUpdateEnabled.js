var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Auto Update Enabled',
    category: 'Virtual Machines',
    description: 'Ensure that VM Auto Update is enabled',
    more_info: "Enabling auto update for the VMs will reduce the security risk of missing security patches",
    recommended_action: 'Enable VM auto update on all virtual machines',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows-or-linux/maintenance-and-updates',
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
				helpers.addResult(results, 0, 'No existing VMs', location);
			} else {
                var reg = 0;
                for(i in virtualMachines.data){
                    var VMConfig = Object.keys(virtualMachines.data[i].osProfile)[2];
                    if(!virtualMachines.data[i].osProfile[VMConfig].enableAutomaticUpdates){
                        helpers.addResult(results, 1, 'VM auto update is not enabled', location, virtualMachines.data[i].id);
                        reg++;
                    }
                }
                if(!reg){
                    helpers.addResult(results, 0, 'VM auto update is enabled', location);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};