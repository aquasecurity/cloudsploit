const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Sets AD Authentication Enabled',
    category: 'Virtual Machine Scale Set',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that Azure Active Directory (AD) authentication is enabled for Virtual Machine Scale Sets.',
    more_info: 'Enabling Azure Active Directory (AD) authentication for VM Scale Sets ensures access from one central point and simplifies access permission management. It allows conditional access by using Role-Based Access Control (RBAC) policies, and enable MFA.',
    recommended_action: 'Enable Active Directory authentication for all Virtual Machines scale sets.',
    link: 'https://learn.microsoft.com/en-us/entra/identity/devices/howto-vm-sign-in-azure-ad-linux',
    apis: ['virtualMachineScaleSets:listAll'],
    realtime_triggers: ['microsoftcompute:virtualmachinescalesets:write', 'microsoftcompute:virtualmachinescalesets:delete', 'microsoftcompute:virtualmachinescalesets:extensions:write', 'microsoftcompute:virtualmachinescalesets:extensions:delete'],
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
                
                const scaleSetExtensions = virtualMachineScaleSet.virtualMachineProfile && virtualMachineScaleSet.virtualMachineProfile.extensionProfile &&
                virtualMachineScaleSet.virtualMachineProfile.extensionProfile.extensions 
                    ? virtualMachineScaleSet.virtualMachineProfile.extensionProfile.extensions 
                    : [];
                const adAuthentication = scaleSetExtensions.length 
                    ? scaleSetExtensions.some((extension) => (extension.properties && extension.properties.type &&
                     (extension.properties.type.toLowerCase() === 'aadloginforwindows' || 
                    extension.properties.type.toLowerCase() === 'aadloginforlinux' || 
                    extension.properties.type.toLowerCase() === 'aadsshloginforlinux')
                    )) 
                    : false;

                if (adAuthentication) {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has Active Directory authentication enabled', location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set has Active Directory authentication disabled', location, virtualMachineScaleSet.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
