const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Sets Boot Diagnostics Enabled',
    category: 'Virtual Machine Scale Set',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensures that boot diagnostics is enabled for Virtual Machine Scale Set.',
    more_info: 'Boot diagnostics is a debugging feature for Azure virtual machines (VM) scale sets that allows diagnosis of VM scale set boot failures. Boot diagnostics enables a user to observe the state of their scale set as it is booting up by collecting serial log information and screenshots.',
    recommended_action: 'Enable boot diagnostics for virtual machine scale set.',
    link: 'https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/boot-diagnostics',
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
                     virtualMachineScaleSet.virtualMachineProfile.diagnosticsProfile &&
                     virtualMachineScaleSet.virtualMachineProfile.diagnosticsProfile.bootDiagnostics && 
                     virtualMachineScaleSet.virtualMachineProfile.diagnosticsProfile.bootDiagnostics.enabled) {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has boot diagnostics enabled', location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set does not have boot diagnostics enabled', location, virtualMachineScaleSet.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
