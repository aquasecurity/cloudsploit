var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM vTPM Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that Virtual Trusted Platform Module (vTPM) is enabled for Azure virtual machines.',
    more_info: 'vTPM is TPM2.0 compliant and enhances security by validating VM boot integrity and providing a secure storage mechanism for keys and secrets. The vTPM enables attestation by measuring the entire boot chain of your VM (UEFI, OS, system, and drivers).',
    recommended_action: 'Modify virtual machine and enable vTPM.',
    link: 'https://learn.microsoft.com/en-us/azure/confidential-computing/virtual-tpms-in-azure-confidential-vm',
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
                if (virtualMachine.securityProfile && virtualMachine.securityProfile.uefiSettings && virtualMachine.securityProfile.uefiSettings.vTpmEnabled) {
                    helpers.addResult(results, 0, 'vTPM is enabled for virtual machine', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'vTPM is not enabled for virtual machine', location, virtualMachine.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
