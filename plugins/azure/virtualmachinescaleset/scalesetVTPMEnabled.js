const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Sets vTPM Enabled',
    category: 'Virtual Machine Scale Set',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensures that Virtual Trusted Platform Module (vTPM) is enabled for Virtual Machine Scale Sets.',
    more_info: 'vTPM is TPM2.0 compliant and enhances security by validating VM boot integrity and providing a secure storage mechanism for keys and secrets. The vTPM enables attestation by measuring the entire boot chain of your VM (UEFI, OS, system, and drivers).',
    recommended_action: 'Modify virtual machine scale set configurations and enable vTPM',
    link: 'https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview',
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
                    virtualMachineScaleSet.virtualMachineProfile.securityProfile.uefiSettings.vTpmEnabled) {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has vTPM enabled', location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set has vTPM disabled', location, virtualMachineScaleSet.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};