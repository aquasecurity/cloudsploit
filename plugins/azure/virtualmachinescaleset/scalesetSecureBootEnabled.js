const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Sets Secure Boot Enabled',
    category: 'Virtual Machine Scale Set',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensures that secure boot is enabled for Virtual Machine Scale Sets.',
    more_info: 'Secure Boot, which is implemented in platform firmware, protects against the installation of malware-based rootkits and boot kits. Secure Boot works to ensure that only signed operating systems and drivers can boot. It establishes a "root of trust" for the software stack on your VMSS.',
    recommended_action: 'Modify virtual machine scale set configurations and enable secure boot',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch#secure-boot',
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

                if (virtualMachineScaleSet.virtualMachineProfile &&
                    virtualMachineScaleSet.virtualMachineProfile.securityProfile &&
                    virtualMachineScaleSet.virtualMachineProfile.securityProfile.uefiSettings &&
                    virtualMachineScaleSet.virtualMachineProfile.securityProfile.uefiSettings.secureBootEnabled) {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has secure boot enabled', location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set have secure boot disabled', location, virtualMachineScaleSet.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};