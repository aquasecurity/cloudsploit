const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automatic OS Upgrades Enabled',
    category: 'Virtual Machines',
    description: 'Ensure that automatic operating system (OS) upgrades are enabled for Microsoft Azure virtual machine scale sets.',
    more_info: 'Enabling automatic OS image upgrades on your scale set helps ease update management by safely and automatically upgrading the OS disk for all instances in the scale set.',
    recommended_action: 'Enable automatic OS upgrades under operating system settings',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-automatic-upgrade',
    apis: ['virtualMachineScaleSets:listAll'],

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

            virtualMachineScaleSets.data.forEach(virtualMachineScaleSet => {
                if (virtualMachineScaleSet.upgradePolicy &&
                    virtualMachineScaleSet.upgradePolicy.automaticOSUpgradePolicy &&
                    virtualMachineScaleSet.upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade) {
                    helpers.addResult(results, 0,
                        'Automatic OS upgrades feature is enabled for virtual machine scale set',
                        location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Automatic OS upgrades feature is not enabled for virtual machine scale set',
                        location, virtualMachineScaleSet.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
