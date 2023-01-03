var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Virtual Machine Has Tags',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Azure virtual machines have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify affected virtual machine and add tags.',
    link: 'https://learn.microsoft.com/bs-latn-ba/azure/virtual-machines/tag-portal',
    apis: ['virtualMachines:listAll', 'virtualMachines:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb){

            var virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }
            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing virtual machines found', location);
                return rcb();
            }

            for (let virtualMachine of virtualMachines.data) { 
                if (!virtualMachine.id) continue;
                
                const virtualMachineData = helpers.addSource(cache, source, ['virtualMachines', 'get', location, virtualMachine.id]);

                if (!virtualMachineData || !virtualMachineData.data || virtualMachineData.err) {
                    helpers.addResult(results, 3, 'unable to query for virtual machine data', location, virtualMachine.id);
                    continue;
                } 
                if (virtualMachineData.data.tags) {
                    helpers.addResult(results, 0, 'Virtual Machine has tags', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual Machine does not have tags', location, virtualMachine.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};