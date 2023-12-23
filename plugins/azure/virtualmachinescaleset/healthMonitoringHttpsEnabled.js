const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Scale Sets Health Monitoring HTTPS Enabled Check',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Checks whether health monitoring is enabled and if HTTPS protocol is configured for VM scale sets.',
    more_info: 'Health monitoring ensures VM health inside the scale set instance. HTTPS protocol provides secure communication for health monitoring.',
    recommended_action: 'Enable health monitoring and configure the extension properties protocol to HTTPS for VM scale sets.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-health-extension',
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
                const scaleSetExtensions = virtualMachineScaleSet.virtualMachineProfile &&
                    virtualMachineScaleSet.virtualMachineProfile.extensionProfile &&
                    virtualMachineScaleSet.virtualMachineProfile.extensionProfile.extensions 
                    ? virtualMachineScaleSet.virtualMachineProfile.extensionProfile.extensions 
                    : [];

                const healthMonitoringEnabled = scaleSetExtensions.length 
                    ? scaleSetExtensions.some((extension) => (
                        extension.properties && (extension.properties.type === 'ApplicationHealthWindows' ||
                        extension.properties.type === 'ApplicationHealthLinux'))
                    )
                    : false;

                const hasHTTPSProtocol = scaleSetExtensions.some((extension) => (
                    extension.properties && extension.properties.settings && extension.properties.settings.protocol &&
                    extension.properties.settings.protocol.toLowerCase() === 'https'
                ));

                if (healthMonitoringEnabled) {
                    if (hasHTTPSProtocol) {
                        helpers.addResult(results, 0,
                            'Virtual Machine Scale Set has HTTPS enabled for health monitoring', location, virtualMachineScaleSet.id);
                    } else {
                        helpers.addResult(results, 2,
                            'Virtual Machine Scale Set does not have HTTPS enabled for health monitoring', location, virtualMachineScaleSet.id);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has health monitoring disabled', location, virtualMachineScaleSet.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
