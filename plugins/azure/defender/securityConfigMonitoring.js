const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Configuration Monitoring',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that Security Configuration Monitoring is enabled in Microsoft Defender.',
    more_info: 'When this setting is enabled, Microsoft Defender for Cloud will monitor virtual machines for security configurations.',
    recommended_action: 'Ensure Security Configuration Monitoring is configured for virtual machines from the Microsoft Defender.',
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
                'systemConfigurationsMonitoringEffect',
                'Monitor Security Configuration', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
