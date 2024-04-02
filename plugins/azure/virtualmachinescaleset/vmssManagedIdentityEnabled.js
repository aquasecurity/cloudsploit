var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Scale Set Managed Identity Enabled',
    category: 'Virtual Machine Scale Set',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that Azure Virtual Machine Scale Sets have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    link: 'https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/qs-configure-portal-windows-vmss',
    recommended_action: 'Modify VM Scale Set and enable managed identity.',
    apis: ['virtualMachineScaleSets:listAll'],
    realtime_triggers: ['microsoftcompute:virtualmachinescalesets:write', 'microsoftcompute:virtualmachinescalesets:delete'],

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
                    helpers.addResult(results, 0, 'Virtual Machine Scale Set has managed identity enabled', location, scaleSet.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual Machine Scale Set does not have managed identity enabled', location, scaleSet.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};