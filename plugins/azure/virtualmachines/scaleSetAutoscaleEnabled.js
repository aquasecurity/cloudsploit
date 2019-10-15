const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Sets Autoscale Enabled',
    category: 'Virtual Machines',
    description: 'Ensures that Virtual Machine scale sets have autoscale enabled for high availability',
    more_info: 'Autoscale automatically creates new instances when certain metrics are surpassed, or can destroy instances that are being underutilized. This creates a highly available scale set.',
    recommended_action: 'Ensure that autoscale is enabled for all Virtual Machine Scale Sets.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-autoscale-overview',
    apis: ['resourceGroups:list', 'virtualMachineScaleSets:list', 'autoscaleSettings:listByResourceGroup'],

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
            }

            if (!virtualMachineScaleSets.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machine Scale Sets found', location);
                return rcb();
            }

            const autoscaleSettings = helpers.addSource(cache, source,
                ['autoscaleSettings', 'listByResourceGroup', location]);

            if (!autoscaleSettings) return rcb();

            if (autoscaleSettings.err || !autoscaleSettings.data) {
                helpers.addResult(results, 3,
                    'Unable to query for AutoScale settings: ' + helpers.addError(autoscaleSettings), location);
                return rcb();
            }

            let autoScaleonVSS = 0;
            virtualMachineScaleSets.data.forEach(virtualMachineScaleSet => {
                    let oneEnabled = false;
                    for (let autoscaleSetting of autoscaleSettings.data) {
                        if (autoscaleSetting.targetResourceUri === virtualMachineScaleSet.id) {
                            if (!autoscaleSetting.enabled ||
                                autoscaleSetting.enabled == false) {
                                continue;
                            } else {
                                autoScaleonVSS++;
                                oneEnabled = true;
                                break;
                            }
                        }
                    }

                if (oneEnabled == false) {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set does not have autoscale enabled', location, virtualMachineScaleSet.id);
                }
            });

            if (autoScaleonVSS == virtualMachineScaleSets.data.length) {
                helpers.addResult(results, 0,
                    'All Virtual Machine Scale Sets have autoscale enabled', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
