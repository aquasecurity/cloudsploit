var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Select vTPM for Azure VMs',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensure Virtual Trusted Platform Module (vTPM) is enabled for Azure virtual machines (VM) to validate boot integrity, securely store keys and secrets, and support advanced threat detection.',
    more_info: 'vTPM is TPM2.0 compliant and enhances security by validating VM boot integrity and providing a secure storage mechanism for keys and secrets.',
    recommended_action: 'Enable vTPM for Azure virtual machines to leverage advanced security features and support Guest Attestation in Azure Security Center.',
    link: 'https://docs.microsoft.com/en-us/azure/security/azure-security-vm-tpm',
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
                if (virtualMachine.securityProfile && virtualMachine.securityProfile.uefiSettings.vTpmEnabled) {
                    helpers.addResult(results, 0, 'vTPM is selected for Azure Virtual Machine', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'vTPM is not selected for Azure Virtual Machine', location, virtualMachine.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
