var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automatic Instance Repairs Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that automatic instance repairs is enabled for Azure virtual machine scale sets.',
    more_info: 'Enabling automatic instance repairs for Azure virtual machine scale sets helps achieve high availability for applications by maintaining a set of healthy instances.',
    recommended_action: 'Enable automatic instance repairs for Azure virtual machine scale sets',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-automatic-instance-repairs',
    apis: ['virtualMachineScaleSets:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb) {
            var virtualMachineScaleSets = helpers.addSource(cache, source,
                ['virtualMachineScaleSets', 'listAll', location]);

            if (!virtualMachineScaleSets) return rcb();

            if (virtualMachineScaleSets.err || !virtualMachineScaleSets.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machine scale sets : ' + helpers.addError(virtualMachineScaleSets), location);
                return rcb();
            }

            if (!virtualMachineScaleSets.data.length) { 
                helpers.addResult(results, 0, 'No existing virtual machines scale sets', location);
                return rcb();
            }

            virtualMachineScaleSets.data.forEach(scaleSet => {
                if (scaleSet.automaticRepairsPolicy && scaleSet.automaticRepairsPolicy.enabled) {
                    helpers.addResult(results, 0, 'Automatic instance repairs is enabled for virtual machine scale set', location, scaleSet.id);
                } else {
                    helpers.addResult(results, 2, 'Automatic instance repairs is not enabled for virtual machine scale set', location, scaleSet.id);
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};