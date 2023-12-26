var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Managed Identity',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that managed identity is being used by Azure Virtual Machines to authenticate with other Azure Services.',
    more_info: 'Using a system assigned managed identity enables Azure resources to authenticate to cloud services (e.g. Azure Key Vault) without storing credentials in code. Once enabled, all necessary permissions can be granted via Azure role-based access control which enhances security by promoting a more secure and streamlined authentication process.',
    recommended_action: 'Ensure that all Azure Virtual Machines have system assigned managed identity enabled.',
    link: 'https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview',
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
                if (virtualMachine.identity && Object.keys(virtualMachine.identity).length) {
                    helpers.addResult(results, 0, 'VM is using a managed identity to interact with other Azure Services', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'VM is not using a managed identity to interact with other Azure Services', location, virtualMachine.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
