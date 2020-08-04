const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Resource Location Matches Resource Group',
    category: 'Azure Policy',
    description: 'Ensures a policy is configured to audit that deployed resource locations match their resource group locations',
    more_info: 'Using Azure Policy to monitor resource location compliance helps ensure that new resources are not launched into locations that do not match their resource group.',
    recommended_action: 'Enable the built-in Azure Policy definition: Audit resource location matches resource group location',
    link: 'https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-portal',
    apis: ['policyAssignments:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        let resourceLocationPolicyAssignment = {};
        const policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/0a914e76-4921-4c19-b460-a2d36003525a';

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
                    'The policy to audit matching resource location to resource group location is assigned', 'global', resourceLocationPolicyAssignment.id);
            } else {
                helpers.addResult(results, 2,
                    'No existing assignment for the resource location matches resource group location policy', 'global');
            }

            callback(null, results, source);
        });
    }
};