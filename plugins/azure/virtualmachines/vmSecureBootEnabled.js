var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Secure Boot Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensures that secure boot is enabled for Azure virtual machines (VM).',
    more_info: 'Secure Boot, which is implemented in platform firmware, protects against the installation of malware-based rootkits and boot kits. Secure Boot works to ensure that only signed operating systems and drivers can boot. It establishes a "root of trust" for the software stack on your VM.',
    recommended_action: 'Modify Virtual Machine and enable secure boot.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch#secure-boot',
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
                if (virtualMachine.securityProfile && virtualMachine.securityProfile.uefiSettings && virtualMachine.securityProfile.uefiSettings.secureBootEnabled) {
                    helpers.addResult(results, 0, 'Secure Boot is enabled for virtual machine', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Secure Boot is not enabled for virtual machine', location, virtualMachine.id);

                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
