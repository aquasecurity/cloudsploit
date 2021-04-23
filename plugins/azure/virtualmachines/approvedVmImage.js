var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Managed VM Machine Image',
    category: 'Virtual Machines',
    description: 'Ensures that VM is launched from a managed VM image.',
    more_info: 'A managed VM image contains the information necessary to create a VM, including the OS and data disks. Virtual Machines should be launched using managed images to ensure security practices and consistency across all the instances.',
    recommended_action: 'Ensure that VM is launced using managed VM image',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/create-vm-generalized-managed',
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
                if (virtualMachine.storageProfile && virtualMachine.storageProfile.imageReference &&
                    virtualMachine.storageProfile.imageReference.id) {
                    helpers.addResult(results, 0, 'VM is launced using Azure managed VM image', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'VM is not launced using Azure managed VM image', location, virtualMachine.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
