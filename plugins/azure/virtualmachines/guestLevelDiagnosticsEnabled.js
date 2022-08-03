var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Guest Level Diagnostics Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that the guest level diagnostics are enabled ',
    more_info: 'Guest Level Diagnostics should be enabled to collect information about VMs processing and state of VM applications.',
    recommended_action: 'Enable guest level diagnostics for all virtual machines',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-vm-agent',
    apis: ['virtualMachines:listAll', 'virtualMachines:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb){

            var virtualMachines = helpers.addSource(cache, source, ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }
            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing virtual machines found', location);
                return rcb();
            }

            for (let virtualMachine of virtualMachines.data) { 
                const virtualMachineData = helpers.addSource(cache, source, ['virtualMachines', 'get', location, virtualMachine.id]);

                if (!(virtualMachineData && virtualMachineData.data && virtualMachineData.data.resources && virtualMachineData.data.resources.length) || virtualMachineData.err) {
                    helpers.addResult(results, 3, 'unable to query for virtual machine data', location, virtualMachine.id);
                } else {
                    const diagnosticSetting = virtualMachineData.data.resources.find(resource => (resource.properties && resource.properties.settings && resource.properties.settings.ladCfg && resource.properties.settings.ladCfg.diagnosticMonitorConfiguration));
                    if (diagnosticSetting) {
                        helpers.addResult(results, 0, 'Guest Level Diagnostics are enabled for the virtual machine', location, virtualMachine.id);
                    } else {
                        helpers.addResult(results, 2, 'Guest Level Diagnostics are disabled for the virtual machine', location, virtualMachine.id);
                    }
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};