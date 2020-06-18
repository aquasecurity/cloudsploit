const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Resources Allowed Locations',
    category: 'Azure Policy',
    description: 'Ensures deployed resources and resource groups belong to the list set in the allowed locations for resource groups policy',
    more_info: 'Setting allowed locations for a service helps ensure the service can only be deployed in expected locations.',
    recommended_action: 'Ensure that all services contain policy definitions that defined allowed locations.',
    link: 'https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-portal',
    apis: ['policyAssignments:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        let resourceLocationPolicyAssignment = {};
        const policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c';

        var globalPolicies = [];

        async.each(locations.policyAssignments, function(location, rcb) {
            const policyAssignments = helpers.addSource(cache, source,
                ['policyAssignments', 'list', location]);

            if (!policyAssignments) return rcb();

            if (!policyAssignments || policyAssignments.err || !policyAssignments.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Policy Assignments: ' + helpers.addError(policyAssignments), location);
                return rcb();
            }

            if (policyAssignments.data.length) {
                globalPolicies = globalPolicies.concat(policyAssignments.data);
            }

            rcb();
        }, function() {
            if (!globalPolicies.length) {
                helpers.addResult(results, 2, 'No existing Policy Assignments found', 'global');
                return callback(null, results, source);
            }

            resourceLocationPolicyAssignment = globalPolicies.find((policyAssignment) => {
                if (policyAssignment.policyDefinitionId) return (policyAssignment.policyDefinitionId.toLowerCase() === policyDefinitionId.toLowerCase());
            });

            if (resourceLocationPolicyAssignment && Object.keys(resourceLocationPolicyAssignment).length) {
                helpers.addResult(results, 0,
                    'The policy to audit resources launched in allowed locations is enabled', 'global', resourceLocationPolicyAssignment.id);
            } else {
                helpers.addResult(results, 2,
                    'No existing assignment for the resources launched in allowed locations policy', 'global');
            }

            callback(null, results, source);
        });
    }
};