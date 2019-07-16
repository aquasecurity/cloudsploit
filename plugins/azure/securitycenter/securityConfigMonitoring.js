const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Configuration Monitoring',
    category: 'Security Center',
    description: 'Ensure that Security Configuration Monitoring is set to audit on the Default Policy',
    more_info: 'By enabling audit on Security Configuration Monitoring, Security Vulnerabilities on machines can be detected, keeping security up to date and following security best practices.',
    recommended_action: '1. Navigate to the Policy service. 2. Select the Assignments blade. 3. Select the ASC Default policy. 4. Select Edit Assignment and Look for Vulnerabilities in Security Configuration On Your Machine Should Be Remediated and select AuditIfNotExists in the drop down menu.',
    link: 'https://docs.microsoft.com/en-us/azure/governance/policy/overview',
    apis: ['policyAssignments:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        var policyDisabled = false;
        var policyId;

        async.each(locations.policyAssignments, (location, rcb) => {
            const policyAssignments = helpers.addSource(cache, source, 
                ['policyAssignments', 'list', location]);
        
            if (!policyAssignments) return rcb();

            if (policyAssignments.err || !policyAssignments.data) {
                helpers.addResult(results,3,
                    'Unable to query PolicyAssignments: ' + helpers.addError(policyAssignments), location);
                return rcb();
            };

            if (!policyAssignments.data.length) {
                return rcb();
            };
            
            for (var policyAssignment of policyAssignments.data) {
                if (policyAssignment !== undefined && 
                    policyAssignment.displayName &&
                    policyAssignment.displayName.indexOf("ASC Default") > -1 && 
                    policyAssignment.parameters &&
                    policyAssignment.parameters.systemConfigurationsMonitoringEffect && 
                    policyAssignment.parameters.systemConfigurationsMonitoringEffect.value &&
                    policyAssignment.parameters.systemConfigurationsMonitoringEffect.value === 'Disabled') {
                    policyDisabled = true;
                    policyId = policyAssignment.id
                    break;
                } else if (policyAssignment.displayName.indexOf("ASC Default") > -1) {
                    policyId = policyAssignment.id;
                    break;
                };
            };
            
            rcb();
        }, function(){
            // Global checking goes here
            if (policyDisabled) {
                helpers.addResult(results, 2,
                    'Security configuration Policy Assignment is Disabled', 'global', policyId);        
            } else {
                helpers.addResult(results, 0,
                    'Security configuration Policy Assignment is Enabled',  'global', policyId);        
            };
            callback(null, results, source);
        });
    }
};
