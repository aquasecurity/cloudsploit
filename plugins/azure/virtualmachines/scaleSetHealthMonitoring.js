const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Sets Health Monitoring Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that health monitoring is enabled for virtual machine scale sets.',
    more_info: 'Scale set health monitoring feature reports on VM health from inside the scale set instance and can be configured to probe on an application endpoint and update the status of the application on that instance. That instance status is checked by Azure to determine whether an instance is eligible for upgrade operations.',
    recommended_action: 'Enable health monitoring for virtual machine scale sets.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-health-extension',
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

            async.each(virtualMachineScaleSets.data, (virtualMachineScaleSet, scb) => {
                const scaleSetExtensions = virtualMachineScaleSet.virtualMachineProfile && virtualMachineScaleSet.virtualMachineProfile.extensionProfile &&
                virtualMachineScaleSet.virtualMachineProfile.extensionProfile.extensions 
                    ? virtualMachineScaleSet.virtualMachineProfile.extensionProfile.extensions 
                    : [];

                const healthMonitoring = scaleSetExtensions.length 
                    ? scaleSetExtensions.some((extension) => (extension.name === 'healthRepairExtension' || extension.type === 'ApplicationHealthLinux')) 
                    : false;

                if (healthMonitoring) {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has health monitoring enabled', location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set has health monitoring disabled', location, virtualMachineScaleSet.id);
                }

                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
