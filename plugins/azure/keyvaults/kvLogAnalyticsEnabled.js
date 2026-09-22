const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Log Analytics Enabled',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures Key Vault Log Analytics logs are being properly delivered to Azure Monitor',
    more_info: 'Enabling Send to Log Analytics ensures that all Key Vault logs are being properly monitored and managed.',
    recommended_action: 'Send all diagnostic logs for Key Vault from the Azure Monitor service to Log Analytics.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-monitor/platform/collect-activity-logs',
    apis: ['vaults:list', 'diagnosticSettings:listByKeyVault'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit record for ' +
                'write read and delete is created for all ' +
                'activities in the system.'
    },
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete','microsoftinsights:diagnosticsettings:write', 'microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.vaults, (location, rcb) => {
            const vaults = helpers.addSource(cache, source,
                ['vaults', 'list', location]);

            if (!vaults) return rcb();

            if (vaults.err || !vaults.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Key Vaults: ' + helpers.addError(vaults), location);
                return rcb();
            }

            if (!vaults.data.length) {
                helpers.addResult(results, 0, 'No existing Key Vaults found', location);
                return rcb();
            }

            vaults.data.forEach(function(vault) {
                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByKeyVault', location, vault.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3,
                        'Unable to query diagnostics settings: ' + helpers.addError(diagnosticSettings), location, vault.id);
                } else if (!diagnosticSettings.data.length) {
                    helpers.addResult(results, 2, 'No existing diagnostics settings', location, vault.id);
                } else {
                    const hasDestination = diagnosticSettings.data.some(ds =>
                        ds.workspaceId || ds.storageAccountId || ds.eventHubAuthorizationRuleId || ds.marketplacePartnerId
                    );

                    if (!hasDestination) {
                        helpers.addResult(results, 2,
                            'Key Vault does not have a diagnostic logs destination configured', location, vault.id);
                        return;
                    }

                    const requiredCategoryGroups = ['audit', 'allLogs'];
                    const missingGroups = requiredCategoryGroups.filter(required =>
                        !diagnosticSettings.data.some(ds =>
                            ds.logs && ds.logs.some(log =>
                                log.categoryGroup && log.categoryGroup.toLowerCase() === required.toLowerCase() && log.enabled
                            )
                        )
                    );

                    if (missingGroups.length) {
                        helpers.addResult(results, 2,
                            `Key Vault diagnostic logs missing required category groups: ${missingGroups.join(', ')}`, location, vault.id);
                    } else {
                        helpers.addResult(results, 0,
                            'Key Vault has diagnostic logs enabled with required category groups', location, vault.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
