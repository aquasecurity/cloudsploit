const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Resource Location Matches Resource Group',
    category: 'Azure Policy',
    description: 'Ensures a policy is configured to audit that deployed resource locations match their resource group locations',
    more_info: 'Using Azure Policy to monitor resource location compliance helps ensure that new resources are not launched into locations that do not match their resource group.',
    recommended_action: 'Enable the built-in Azure Policy definition: Audit resource location matches resource group location',
    link: 'https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-portal',
    apis: ['policyAssignments:list', 'resourceGroups:list', 'resources:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};

        let resourceLocationPolicyAssignment = {};
        const policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/0a914e76-4921-4c19-b460-a2d36003525a';

        const policyAssignments = helpers.addSource(cache, source,
            ['policyAssignments', 'list', 'global']);

        if (!policyAssignments) return rcb();

        if (!policyAssignments || policyAssignments.err || !policyAssignments.data) {
            helpers.addResult(results, 3,
                'Unable to query for Policy Assignments: ' + helpers.addError(policyAssignments), 'global');
            return callback();
        }

        if (!policyAssignments.data.length) {
            helpers.addResult(results, 2, 'No existing Policy Assignments found', 'global');
            return callback();
        }


        resourceLocationPolicyAssignment = policyAssignments.data.find((policyAssignment) => {
            if (policyAssignment.policyDefinitionId) return (policyAssignment.policyDefinitionId === policyDefinitionId)
        });


        if (resourceLocationPolicyAssignment && Object.keys(resourceLocationPolicyAssignment).length) {
            helpers.addResult(results, 0,
                'The policy to audit matching resource location to resource group location is assigned', 'global', resourceLocationPolicyAssignment.id);
        } else {
            helpers.addResult(results, 2,
                'No existing assignment for the resource location matches resource group location policy', 'global');
        }

        callback(null, results, source);
    }
};