var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Security Type',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensures that Azure virtual machines have desired security type configured.',
    more_info: 'Using advanced security features for virtual machines boost security by verifying the integrity of VMs during boot-up and safeguarding data in use. They defend against advanced threats, encrypt sensitive data, and ensure compliance with high security standards.',
    recommended_action: 'Set the desired security type for all Azure virtual machines',
    link: 'https://learn.microsoft.com/en-us/azure/confidential-computing',
    apis: ['virtualMachines:listAll'],
    realtime_triggers: ['microsoftcompute:virtualmachines:write', 'microsoftcompute:virtualmachines:delete'],
    settings: {
        desired_security_type: {
            name: 'VM Desired Security Type',
            description: 'Desired security type i.e. "trustedlaunch" or "confidentialvm".',
            regex: '^(trustedlaunch|confidentialvm)$',
            default: 'trustedlaunch'

        },
    },
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var securityTypes = ['trustedlaunch', 'confidentialvm'];
        var config = settings.desired_security_type || this.settings.desired_security_type.default;

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
                const configuredSecuritytype = virtualMachine.securityProfile && virtualMachine.securityProfile.securityType.toLowerCase();
                if (securityTypes.indexOf(configuredSecuritytype) >= securityTypes.indexOf(config)) {
                    helpers.addResult(results, 0, `${configuredSecuritytype} is configured as security type for virtual machine`, location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, `${config} is not configured as security type for virtual machine`, location, virtualMachine.id);
                }
                
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
