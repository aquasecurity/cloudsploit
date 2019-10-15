var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Auto Update Enabled',
    category: 'Virtual Machines',
    description: 'Ensures that VM Auto Update is enabled for virtual machines',
    more_info: 'Enabling Auto Update on Azure virtual machines reduces the security risk of missing security patches.',
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
                helpers.addResult(results, 3, 'Unable to query for Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }
            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing virtual machines found', location);
            } else {
                var reg = 0;
                for(i in virtualMachines.data){
                    if (virtualMachines.data[i].osProfile &&
                        Object.keys(virtualMachines.data[i].osProfile) &&
                        Object.keys(virtualMachines.data[i].osProfile).length>1
                    ) {
                        var VMConfig = Object.keys(virtualMachines.data[i].osProfile)[2];
                        if (!virtualMachines.data[i].osProfile[VMConfig].enableAutomaticUpdates) {
                            helpers.addResult(results, 2, 'VM Auto Update is not enabled for this virtual machine: ' + virtualMachines.data[i].name, location, virtualMachines.data[i].id);
                            reg++;
                        }
                    }
                }
                if(!reg){
                    helpers.addResult(results, 0, 'VM Auto Update is enabled for all virtual machines', location);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};