const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor IP Forwarding',
    category: 'Security Center',
    domain: 'Management and Governance',
    description: 'Ensures that Virtual Machine IP Forwarding Monitoring is enabled in Security Center',
    more_info: 'IP Forwarding feature should be monitored to meet you organization\'s security compliance requirements.',
    recommended_action: 'Enable IP Forwarding Monitoring by ensuring AuditIfNotExists setting is used for \'IP Forwarding on your virtual machine should be disabled\' from the Azure Security Center.',
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
                'disableIPForwardingMonitoringEffect',
                'IP Forwarding Monitoring', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};