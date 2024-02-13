var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Security Type',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Trusted launch is selected for Azure virtual machines.',
    more_info: 'Trusted launch protects against advanced and persistent attack techniques. Trusted launch is composed of several, coordinated infrastructure technologies that can be enabled independently. Each technology provides another layer of defense against sophisticated threats.',
    recommended_action: 'Select Trusted launch as security type for Azure virtual machines.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-portal?tabs=portal%2Cportal3%2Cportal2',
    apis: ['virtualMachines:listAll'],
    realtime_triggers: ['microsoftcompute:virtualmachines:write', 'microsoftcompute:virtualmachines:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb) {
            var virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            virtualMachines.data.forEach(virtualMachine => {
                if (virtualMachine.securityProfile && virtualMachine.securityProfile.securityType == 'TrustedLaunch') {
                    helpers.addResult(results, 0, 'Trusted launch is selected as security type for virtual machine', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Trusted launch is not selected as security type for virtual machine', location, virtualMachine.id);
                }
                
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
