const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Availability Set Enabled',
    category: 'Virtual Machines',
    description: 'Ensures that Virtual Machines have Availability Set enabled',
    more_info: 'Enabling Availability Sets ensures that during either a planned or unplanned maintenance event, the virtual machine will still be available.',
    recommended_action: 'Virtual Machine Availability Sets can only be configured when creating a new virtual machine. Recreate the Virtual Machine with Availability Sets enabled.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/manage-availability',
    apis: ['virtualMachines:listAll'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, (location, rcb) => {

            const virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            virtualMachines.data.forEach(virtualMachine => {
                if (virtualMachine.availabilitySet) {
                    helpers.addResult(results, 0,
                        'The Virtual Machine has Availability Set enabled', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2,
                        'The Virtual Machine does not have Availability Set enabled', location, virtualMachine.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};