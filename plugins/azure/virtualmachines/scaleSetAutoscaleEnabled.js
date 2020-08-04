const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Sets Autoscale Enabled',
    category: 'Virtual Machines',
    description: 'Ensures that Virtual Machine scale sets have autoscale enabled for high availability',
    more_info: 'Autoscale automatically creates new instances when certain metrics are surpassed, or can destroy instances that are being underutilized. This creates a highly available scale set.',
    recommended_action: 'Ensure that autoscale is enabled for all Virtual Machine Scale Sets.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-autoscale-overview',
    apis: ['virtualMachineScaleSets:listAll', 'autoscaleSettings:listBySubscription'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachineScaleSets, (location, rcb) => {

            const virtualMachineScaleSets = helpers.addSource(cache, source,
                ['virtualMachineScaleSets', 'listAll', location]);

            if (!virtualMachineScaleSets) return rcb();

            if (virtualMachineScaleSets.err || !virtualMachineScaleSets.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Virtual Machine Scale Sets: ' + helpers.addError(virtualMachineScaleSets), location);
                return rcb();
            }

            if (!virtualMachineScaleSets.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machine Scale Sets found', location);
                return rcb();
            }

            const autoscaleSettings = helpers.addSource(cache, source,
                ['autoscaleSettings', 'listBySubscription', location]);

            if (!autoscaleSettings || autoscaleSettings.err || !autoscaleSettings.data) {
                helpers.addResult(results, 3,
                    'Unable to query for AutoScale settings: ' + helpers.addError(autoscaleSettings), location);
                return rcb();
            }

            if (!autoscaleSettings.data.length) {
                helpers.addResult(results, 2,
                    'No Virtual Machine Scale Sets have autoscale enabled', location);
                return rcb();
            }

            var asMap = {};
            autoscaleSettings.data.forEach(function(autoscaleSetting) {
                if (autoscaleSetting.targetResourceUri) {
                    asMap[autoscaleSetting.targetResourceUri.toLowerCase()] = autoscaleSetting;
                }
            });

            virtualMachineScaleSets.data.forEach(virtualMachineScaleSet => {
                if (virtualMachineScaleSet.id &&
                    asMap[virtualMachineScaleSet.id.toLowerCase()] &&
                    asMap[virtualMachineScaleSet.id.toLowerCase()].enabled) {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has autoscale enabled', location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set does not have autoscale enabled', location, virtualMachineScaleSet.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
