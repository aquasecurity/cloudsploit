var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Agent Enabled',
    category: 'Virtual Machines',
    description: 'Ensures that the VM Agent is enabled for virtual machines',
    more_info: 'The VM agent must be enabled on Azure virtual machines in order to enable Azure Security Center for data collection.',
    recommended_action: 'Enable the VM agent for all virtual machines.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-vm-agent',
    apis: ['virtualMachines:listAll'],
    compliance: {
        hipaa: 'HIPAA requires the logging of all activity ' +
                'including access and all actions taken. VM ' +
                'agent is needed to provide the necessary logs.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb){

            var virtualMachines = helpers.addSource(cache, source, ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }
            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing virtual machines found', location);
                return rcb();
            }

            virtualMachines.data.forEach(virtualMachine => {
                if (virtualMachine.osProfile &&
                    virtualMachine.osProfile.linuxConfiguration) {
                    if (virtualMachine.osProfile.linuxConfiguration.provisionVMAgent) {
                        helpers.addResult(results, 0, 'VM Agent is enabled for this virtual machine: ' + virtualMachine.name, location, virtualMachine.id);
                    } else {
                        helpers.addResult(results, 2, 'VM Agent is not enabled for this virtual machine: ' + virtualMachine.name, location, virtualMachine.id);
                    }
                } else if (virtualMachine.osProfile &&
                    virtualMachine.osProfile.windowsConfiguration) {
                    if (virtualMachine.osProfile.windowsConfiguration.provisionVMAgent) {
                        helpers.addResult(results, 0, 'VM Agent is enabled for this virtual machine: ' + virtualMachine.name, location, virtualMachine.id);
                    } else {
                        helpers.addResult(results, 2, 'VM Agent is not enabled for this virtual machine: ' + virtualMachine.name, location, virtualMachine.id);
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};