const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Sets Trusted Launch Enabled',
    category: 'Virtual Machine Scale Set',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensures that trusted launch security is enabled for Virtual Machine Scale Set.',
    more_info: 'Enabling trusted launch works in seamless way to improve the security of VM scale sets. Trusted launch protects against advanced and persistent attack techniques. It is composed of several, coordinated infrastructure technologies that can be enabled independently, providing another layer of defense against sophisticated threats.',
    recommended_action: 'Remove existing Virtual Machine Scale Set and create a new one with trusted launch enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch',
    apis: ['virtualMachineScaleSets:listAll'],
    realtime_triggers: ['microsoftcompute:virtualmachinescalesets:write', 'microsoftcompute:virtualmachinescalesets:delete'],

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
            
            for (let virtualMachineScaleSet of virtualMachineScaleSets.data) {
                if (!virtualMachineScaleSet.id) continue;

                if (virtualMachineScaleSet.virtualMachineProfile &&
                     virtualMachineScaleSet.virtualMachineProfile.securityProfile &&
                     virtualMachineScaleSet.virtualMachineProfile.securityProfile.securityType && 
                     virtualMachineScaleSet.virtualMachineProfile.securityProfile.securityType.toLowerCase() == 'trustedlaunch') {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has trusted launch enabled', location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set has trusted launch disabled', location, virtualMachineScaleSet.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
