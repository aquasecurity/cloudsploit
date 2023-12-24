const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Approved Extensions',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that approved virtual machine extensions are installed.',
    more_info: 'Extensions are small applications that provide post-deployment configuration and automation on Azure VMs. Extensions installed should be approved by the organization to meet the organizational security requirements.',
    recommended_action: 'Uninstall unapproved virtual machine extensions',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/overview',
    apis: ['virtualMachines:listAll', 'virtualMachineExtensions:list'],
    settings: {
        vmss_approved_extensions: {
            name: 'Approved VM extensions',
            description: 'List of comma separated approved extension names',
            regex: '^.*$',
            default: 'healthRepairExtension'
        }
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        const config = {
            approvedExtensions: settings.vmss_approved_extensions || this.settings.vmss_approved_extensions.default
        };

        if (!config.approvedExtensions.length) return callback(null, results, source);

        var extensionsList = config.approvedExtensions.split(',');

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
            for (let virtualMachineScaleSet of virtualMachineScaleSets.data){
                
                const scaleSetExtensions = virtualMachineScaleSet.virtualMachineProfile && virtualMachineScaleSet.virtualMachineProfile.extensionProfile &&
                virtualMachineScaleSet.virtualMachineProfile.extensionProfile.extensions 
                    ? virtualMachineScaleSet.virtualMachineProfile.extensionProfile.extensions 
                    : [];
                
                if (!scaleSetExtensions.length) {
                    helpers.addResult(results, 0, 'No VMSS Extensions found', location);
                    continue;
                }

                scaleSetExtensions.forEach(function(vmssEx) {
                    let found = extensionsList.some(extension => extension.trim() === vmssEx.name);

                    if (found) {
                        helpers.addResult(results, 0, `${vmssEx.name} extension is approved by the organization`, location, virtualMachineScaleSet.id);
                    } else {
                        helpers.addResult(results, 2, `${vmssEx.name} extension is not approved by the organization`, location, virtualMachineScaleSet.id);
                    }
                });
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
