var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Auto Update Enabled',
    category: 'Virtual Machines',
    description: 'Ensures that VM Auto Update is enabled for virtual machines',
    more_info: 'Enabling Auto Update on Azure virtual machines reduces the security risk of missing security patches.',
    recommended_action: 'Enable VM auto update on all virtual machines',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows-or-linux/maintenance-and-updates',
    apis: ['virtualMachines:listAll'],
    compliance: {
        pci: 'PCI requires all system components have the latest updates ' +
            'and patches installed within a month of release.'
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

            var found = false;
            virtualMachines.data.forEach(virtualMachine => {
                if (virtualMachine.osProfile &&
                    virtualMachine.osProfile.windowsConfiguration) {
                    found = true;
                    if (virtualMachine.osProfile.windowsConfiguration.enableAutomaticUpdates) {
                        helpers.addResult(results, 0, 'Automatic updates are enabled for this virtual machine: ' + virtualMachine.name, location, virtualMachine.id);
                    } else {
                        helpers.addResult(results, 2, 'Automatic updates are not enabled for this virtual machine: ' + virtualMachine.name, location, virtualMachine.id);
                    }
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'Automatic updates are enabled on all Windows virtual machines', location);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};