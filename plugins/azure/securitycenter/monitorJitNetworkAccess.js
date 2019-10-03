const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor JIT Network Access',
    category: 'Security Center',
    description: 'Ensures Just In Time Network Access monitoring is enabled in Security Center.',
    more_info: 'When this setting is enabled, Security Center audits Just In Time Network Access on all virtual machines (Windows and Linux as well) to enhance data protection at rest',
    recommended_action: '1. Go to Azure Security Center 2. Click On the security policy to Open Policy Management Blade. 3. Click Subscription View 4. Click on Subscription Name to open Security Policy Blade for the Subscription. 5. Expand Compute And Apps 6. Ensure that JIT Network Access is not set to Disabled',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        let policyDisabled = false;

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
                    policyAssignment.parameters.jitNetworkAccessMonitoringEffect && 
                    policyAssignment.parameters.jitNetworkAccessMonitoringEffect.value &&
                    policyAssignment.parameters.jitNetworkAccessMonitoringEffect.value === 'Disabled') {
                    policyDisabled = true;
                    policyId = policyAssignment.id;
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
                    'ASC policy setting Monitor JIT Network Access is Disabled', 'global', policyId);        
            } else {
                helpers.addResult(results, 0,
                    'ASC policy setting Monitor JIT Network Access is not Disabled', 'global', policyId);        
            };
            callback(null, results, source);
        });
    }
};
