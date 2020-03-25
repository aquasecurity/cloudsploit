const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Set Multi Az',
    category: 'Virtual Machines',
    description: 'Ensures that Virtual Machine Scale Sets are created to be cross-AZ for high availability',
    more_info: 'Having Virtual Machine Scale Sets in multiple zones increases durability and availability. If there is a catastrophic instance in one zone, the scale set will still be available.',
    recommended_action: 'Multiple zones can only be created when instantiating a new Scale Set. Ensure that the Scale Set is in multiple zones when creating a new Scale Set.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-autoscale-overview',
    apis: ['resourceGroups:list', 'virtualMachineScaleSets:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachineScaleSets, (location, rcb) => {

            const virtualMachineScaleSets = helpers.addSource(cache, source,
                ['virtualMachineScaleSets', 'list', location]);

            if (!virtualMachineScaleSets) return rcb();

            if (virtualMachineScaleSets.err || !virtualMachineScaleSets.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Virtual Machine Scale Sets: ' + helpers.addError(virtualMachineScaleSets), location);
                return rcb();
            };

            if (!virtualMachineScaleSets.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machine Scale Sets found', location);
                return rcb();
            };

            let isSingleZone = false;

            virtualMachineScaleSets.data.forEach(virtualMachineScaleSet => {
                if (!virtualMachineScaleSet.zones ||
                    virtualMachineScaleSet.zones.length <= 1) {
                    isSingleZone = true;
                    helpers.addResult(results, 2,
                        'The Virtual Machine Scale Set is not in multiple zones', location,  virtualMachineScaleSet.id);
                };
            });

            if (!isSingleZone) {
                helpers.addResult(results, 0,
                    'All Virtual Machine Scale Sets are in multiple zones', location);
            };

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
