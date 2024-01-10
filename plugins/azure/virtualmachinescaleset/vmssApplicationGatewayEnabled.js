const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Scale Set Application Gateway Enabled',
    category: 'Virtual Machine Scale Set',
    domain: 'Compute',
    description: 'Ensures that Azure Virtual Machine scale sets has Application Gateway enabled.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-networking?tabs=portal1',
    recommended_action: 'Modify VM scale set and add application gateway.',
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
                let found = false;
                if (virtualMachineScaleSet.virtualMachineProfile &&
                    virtualMachineScaleSet.virtualMachineProfile.networkProfile &&
                    virtualMachineScaleSet.virtualMachineProfile.networkProfile.networkInterfaceConfigurations) {
                    for (let config of virtualMachineScaleSet.virtualMachineProfile.networkProfile.networkInterfaceConfigurations) {
                        if (config.properties && config.properties.ipConfigurations) {
                            for (let ipConfig of config.properties.ipConfigurations) {
                                if (ipConfig.properties.applicationGatewayBackendAddressPools && 
                                ipConfig.properties.applicationGatewayBackendAddressPools.length > 0) {
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (found) {
                            break;
                        }
                    }
                }
                if (found) {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has application gateway enabled', location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set does not have application gateway enabled', location, virtualMachineScaleSet.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
