const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor System Updates',
    category: 'Security Center',
    description: 'Ensure that Monitor System Updates is enabled in Security Center.',
    more_info: 'When this setting is enabled, Security Center will audit any updates that the uperating System or VM needs.',
    recommended_action: '1. Go to Azure Security Center 2. Click on Security policy 3. Click on your Subscription Name 4. Look for the "Monitor System Updates" setting. 5. Ensure that it is not set to Disabled',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        var policyDisabled = false;
        var policyId = '';

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
                    policyAssignment.parameters.systemUpdatesMonitoringEffect &&
                    policyAssignment.parameters.systemUpdatesMonitoringEffect.value &&
                    policyAssignment.parameters.systemUpdatesMonitoringEffect.value === 'Disabled') {
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
                    'ASC Default policy setting: Monitor System Updates is Disabled', 'global', policyId);        
            } else {
                helpers.addResult(results, 0,
                    'ASC Default policy setting: Monitor System Updates is not Disabled',  'global', policyId);        
            };
            callback(null, results, source);
        });
    }
};