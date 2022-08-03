const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Next Generation Firewall',
    category: 'Security Center',
    domain: 'Management and Governance',
    description: 'Ensures that Next Generation Firewall (NGFW) Monitoring is enabled in Security Center',
    more_info: 'When this setting is enabled, Security Center will search for deployments where a NGFW is recommended.',
    recommended_action: 'Enable Next Generation Firewall Monitoring by ensuring AuditIfNotExists setting is used for \'All network ports should be restricted on network security groups associated to your virtual machine\' from the Azure Security Center.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],

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