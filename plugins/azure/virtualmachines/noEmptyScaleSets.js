var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'No Empty Scale Sets',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that virtual machine scale sets have virtual machine instances attached.',
    more_info: 'Azure virtual machine scale sets let you create and manage a group of load balanced VMs. Scale sets with no vm instances should be deleted to save cost of unused resources',
    recommended_action: 'Delete virtual machine scale sets that have no virtual machine instances',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/overview',
    apis: ['virtualMachineScaleSets:listAll', 'virtualMachineScaleSetVMs:list'],

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
                var scaleSetVMs = helpers.addSource(cache, source,
                    ['virtualMachineScaleSetVMs', 'list', location, scaleSet.id]);

                if (!scaleSetVMs || scaleSetVMs.err || !scaleSetVMs.data) {
                    helpers.addResult(results, 3, 'Unable to query for virtual machine scale set VM instances : ' + helpers.addError(scaleSetVMs), location);
                } else {

                    if (scaleSetVMs.data.length) {
                        helpers.addResult(results, 0, 'Virtual machine scale set has VM instances attached', location, scaleSet.id);
                    } else {
                        helpers.addResult(results, 2, 'Virtual machine scale set has no VM instances attached', location, scaleSet.id);
                    }
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
