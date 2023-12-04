var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Azure VMs Security Type',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensure Trusted Launch is selected for Azure virtual machines (VM) to enhance security against advanced and persistent attack techniques.',
    more_info: 'Trusted Launch provides additional security features on Gen 2 virtual machines, offering defense against sophisticated threats.',
    recommended_action: 'Enable Trusted Launch for Azure virtual machines to leverage coordinated infrastructure technologies for enhanced security.',
    link: 'https://docs.microsoft.com/en-us/azure/security/benchmark/azure-benchmark',
    apis: ['virtualMachines:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb) {
            var virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            virtualMachines.data.forEach(virtualMachine => {
                if (virtualMachine.securityProfile && virtualMachine.securityProfile.securityType == 'TrustedLaunch') {
                    helpers.addResult(results, 0, 'Trusted Launch is selected as security type for Azure Virtual Machine', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Trusted Launch is not selected as security type for Azure Virtual Machine', location, virtualMachine.id);
                }
                
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
