var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Password Authentication Disabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that password authentication is disabled on Azure virtual machines.',
    more_info: 'SSH provides secure sign-ins over unsecured connections. Although SSH provides an encrypted connection, using passwords with SSH connections still leaves the VM vulnerable so it is recommended to connect to VM over SSH instead of password.',
    recommended_action: 'Disable password authentication on Azure virtual machine',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/linux/create-ssh-keys-detailed',
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
                helpers.addResult(results, 3, 'Unable to query for virtualMachines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            virtualMachines.data.forEach(virtualMachine => {
                if (virtualMachine.osProfile && virtualMachine.osProfile.windowsConfiguration) {
                    helpers.addResult(results, 0, 'SSH authentication is not supported in Windows VM', location, virtualMachine.id);
                } else {
                    if (virtualMachine.osProfile && virtualMachine.osProfile.linuxConfiguration &&
                        virtualMachine.osProfile.linuxConfiguration.disablePasswordAuthentication) {
                        helpers.addResult(results, 0, 'Password authentication is disabled on virtual machine', location, virtualMachine.id);
                    } else {
                        helpers.addResult(results, 2, 'Password authentication is not disabled on virtual machine', location, virtualMachine.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};