var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Scale Set Managed Identity Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Azure Virtual Machine scale sets have managed identity enabled.',
    more_info: 'Managed identities for Azure resources provide Azure services with an automatically managed identity in Microsoft Entra ID. You can use this identity to authenticate to any service that supports Microsoft Entra authentication, without having credentials in your code.',
    link: 'https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/qs-configure-portal-windows-vmss',
    recommended_action: 'Modify VM scale set and enable user or system assigned identities.',
    apis: ['virtualMachineScaleSets:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.vmScaleSet, function(location, rcb) {

            var vmScaleSets = helpers.addSource(cache, source, ['virtualMachineScaleSets', 'listAll', location]);

            if (!vmScaleSets) return rcb();

            if (vmScaleSets.err || !vmScaleSets.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Machine Scale Sets: ' + helpers.addError(vmScaleSets), location);
                return rcb();
            }
            if (!vmScaleSets.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machine Scale Sets found', location);
                return rcb();
            }
            for (let scaleSet of vmScaleSets.data) {
                if (!scaleSet.id) continue;

                if (scaleSet.identity && scaleSet.identity.type){
                    helpers.addResult(results, 0, 'VM scale set has managed identity enabled', location, scaleSet.id);
                } else {
                    helpers.addResult(results, 2, 'VM scale set does not have managed identity enabled', location, scaleSet.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};