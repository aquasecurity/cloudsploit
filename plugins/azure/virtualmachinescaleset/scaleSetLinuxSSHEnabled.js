var async = require('async');

var helpers = require('../../../helpers/azure');


module.exports = {
    title: 'VM Scale Set Linux SSH Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Azure Virtual Machine scale sets with Linux OS has SSH enabled.',
    more_info: 'SSH is an encrypted connection protocol that allows secure sign-ins over unsecured connections. SSH is the default connection protocol for Linux VMs hosted in Azure.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/linux/ssh-from-windows',
    recommended_action: 'Remove existing scale set and create new with SSH enabled',
    apis: ['virtualMachineScaleSets:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.vmScaleSet, function(location, rcb) {

            var vmScaleSets = helpers.addSource(cache, source, ['virtualMachineScaleSets', 'listAll', location]);

            if (!vmScaleSets) return rcb();

            if (vmScaleSets.err || !vmScaleSets.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Machine Scale Sets: ' + helpers.addError(vmScaleSets), location);
                return rcb();
            }
            if (!vmScaleSets.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machine Scale Sets found', location);
                return rcb();
            }
            for (let scaleSet of vmScaleSets.data) {
                if (!scaleSet.id) continue;

                if ((scaleSet.virtualMachineProfile.storageProfile && scaleSet.virtualMachineProfile.storageProfile.osDisk &&
                scaleSet.virtualMachineProfile.storageProfile.osDisk.osType && 
                scaleSet.virtualMachineProfile.storageProfile.osDisk.osType.toLowerCase() === 'linux')){

                    if (scaleSet.virtualMachineProfile  && scaleSet.virtualMachineProfile.osProfile &&
                    scaleSet.virtualMachineProfile.osProfile.linuxConfiguration &&
                    scaleSet.virtualMachineProfile.osProfile.linuxConfiguration.ssh){
                        helpers.addResult(results, 0, 'VM scale set for linux has SSH enabled', location, scaleSet.id);
                    } else {
                        helpers.addResult(results, 2, 'VM scale set for linux does not have SSH enabled', location, scaleSet.id);
                    }
                } else {
                    continue;
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};