const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor External Accounts with Write Permissions',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that External Accounts with Write Permissions are being Monitored in Microsoft Defender.',
    more_info: 'External Accounts with Write Permissions should be monitored to meet you organization\'s security compliance requirements.',
    recommended_action: 'Enable Monitor for External Accounts with Write Permissions by ensuring AuditIfNotExists setting is used for \'External accounts with write permissions should be removed from your subscription\' from the Microsoft Defender.',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference',
    apis: ['policyAssignments:list'],
    realtime_triggers: ['microsoftauthorization:policyassignments:write','microsoftauthorization:policyassignments:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, function(location, rcb) {

            const policyAssignments = helpers.addSource(cache, source,
                ['policyAssignments', 'list', location]);

            helpers.checkPolicyAssignment(policyAssignments,
                'identityRemoveExternalAccountWithWritePermissionsMonitoringEffect',
                'Monitor for External Accounts with Write Permissions', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};