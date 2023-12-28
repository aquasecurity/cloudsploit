const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Sets Trusted Launch Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Trusted launch security option is enabled for virtual machine scale sets.',
    more_info: 'Trusted launch protects against advanced and persistent attack techniques. Trusted launch is composed of several, coordinated infrastructure technologies that can be enabled independently. Each technology provides another layer of defense against sophisticated threats.',
    recommended_action: 'Modify VMSS configurations and enable trusted launch.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch',
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
            
            for (let virtualMachineScaleSet of virtualMachineScaleSets.data) {

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
