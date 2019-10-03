var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Classic Instances',
    category: 'Virtual Machines',
    description: 'Ensures Azure Resource Manager is being used for instances instead of Cloud service(VM classic)',
    more_info: 'ARM is the latest and more secure method of launching Azure resources. VM Classic should not be used.',
    recommended_action: 'Migrate instances from Cloud Service to ARM',
    link: 'https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-overview',
    apis: ['resources:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.resources, function(location, rcb){

            var resources = helpers.addSource(cache, source, 
                ['resources', 'list', location]);

            if (!resources) return rcb();

            if (resources.err || !resources.data) {
                helpers.addResult(results, 3, 'Unable to query Resources: ' + helpers.addError(resources), location);
                return rcb();
            };

            if (!resources.data.length) {
                helpers.addResult(results, 0, 'No existing Resources', location);
                return rcb();
            };

            var classicVms = 0;

            resources.data.forEach(resource => {
                if (resource.type &&
                    resource.type == "Microsoft.ClassicCompute/virtualMachines") {
                    classicVms++;
                };
            });

            if (classicVms) {
                helpers.addResult(results, 1, `There are ${classicVms} classic VM instances`, location);
            } else {
                helpers.addResult(results, 0, 'There are no classic VM instances.', location);
            };

            rcb();
        }, function(){
            callback(null, results, source)
        });
    }
}; 