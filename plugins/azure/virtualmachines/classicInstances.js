var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Classic Instances',
    category: 'Virtual Machines',
    description: 'Ensures Azure Resource Manager is being used for instances instead of Cloud Services (VM Classic)',
    more_info: 'ARM is the latest and most secure method of launching Azure resources. VM Classic should not be used.',
    recommended_action: 'Migrate instances from Cloud Service to ARM.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-overview',
    apis: ['virtualMachines:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb){
            var virtualMachines = helpers.addSource(cache, source, 
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtualMachines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            var classicVms = 0;

            virtualMachines.data.forEach(resource => {
                if (resource.type &&
                    resource.type.toLowerCase() == 'microsoft.classiccompute/virtualmachines') {
                    classicVms++;
                }
            });

            if (classicVms) {
                helpers.addResult(results, 2, `There are ${classicVms} classic VM instances`, location);
            } else {
                helpers.addResult(results, 0, 'There are no classic VM instances', location);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 