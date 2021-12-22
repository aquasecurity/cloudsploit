var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disable Automatic IAM Grants',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Disable Automatic IAM Grants for Default Service Accounts" policy is enforced at the organization level.',
    more_info: 'By default, service accounts get the editor role when created. To improve access security, disable the automatic IAM role grant.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Disable Automatic IAM Grants for Default Service Accounts" constraint is enforced at the organization level.',
    apis: ['organizations:list', 'organizations:listOrgPolicies'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let listOrgPolicies = helpers.addSource(cache, source,
            ['organizations', 'listOrgPolicies', 'global']);

        if (!listOrgPolicies) return callback(null, results, source);

        if (listOrgPolicies.err || !listOrgPolicies.data) {
            helpers.addResult(results, 3, 'Unable to query organization policies', 'global', null, null, listOrgPolicies.err);
            return callback(null, results, source);
        }

        if (!listOrgPolicies.data.length) {
            helpers.addResult(results, 0, 'No organization policies found', 'global');
            return callback(null, results, source);
        }
        let orgPolicies = listOrgPolicies.data[0];

        helpers.checkOrgPolicy(orgPolicies, 'iam.automaticIamGrantsForDefaultServiceAccounts', 'booleanPolicy', true, false, 'Disable Automatic IAM Grants for Default Service Accounts', results);

        return callback(null, results, source);
    }
};