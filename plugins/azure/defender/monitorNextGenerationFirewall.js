const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Next Generation Firewall',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that Next Generation Firewall (NGFW) Monitoring is enabled in Microsoft Defender.',
    more_info: 'When this setting is enabled, Microsoft Defender for Cloud will search for deployments where a NGFW is recommended.',
    recommended_action: 'Enable Next Generation Firewall Monitoring by ensuring AuditIfNotExists setting is used for \'All network ports should be restricted on network security groups associated to your virtual machine\' from the Microsoft Defender.',
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
                'nextGenerationFirewallMonitoringEffect',
                'Next Generation Firewall Monitoring', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};