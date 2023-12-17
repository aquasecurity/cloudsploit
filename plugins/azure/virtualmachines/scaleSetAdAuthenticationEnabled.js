const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
title: 'Scale Sets Active Directory Authentication Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Azure Active Directory (AD) authentication is enabled for virtual machine scale sets.',
    more_info: 'Organizations can now improve the security of virtual machine Scale Sets in Azure by integrating with Azure Active Directory (AD) authentication. Enabling Azure Active Directory (AD) authentication for Azure virtual machine scale set ensures access to VMs from one central point and simplifies access permission management.',
    recommended_action: 'Enable Azure Active Directory authentication for Azure virtual machines scale sets.',
    link: 'https://learn.microsoft.com/en-us/entra/identity/devices/howto-vm-sign-in-azure-ad-linux',
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
                const scaleSetExtensions = virtualMachineScaleSet.virtualMachineProfile && virtualMachineScaleSet.virtualMachineProfile.extensionProfile &&
                virtualMachineScaleSet.virtualMachineProfile.extensionProfile.extensions 
                    ? virtualMachineScaleSet.virtualMachineProfile.extensionProfile.extensions 
                    : [];
                const adAuthentication = scaleSetExtensions.length 
                    ? scaleSetExtensions.some((extension) => (extension.properties.type === 'AADLoginForWindows' || 
                    extension.properties.type === 'AADLoginForLinux' || extension.properties.type === 'AADSSHLoginForLinux'
                    )) 
                    : false;

                if (adAuthentication) {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has active directory authentication enabled', location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set has active directory authentication disabled', location, virtualMachineScaleSet.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
