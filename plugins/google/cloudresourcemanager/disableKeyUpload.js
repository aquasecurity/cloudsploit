var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disable Service Account Key Upload',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Disable Service Account Key Upload" policy is enforced at the GCP organization level.',
    more_info: 'User-managed keys can impose a security risk if they are not handled correctly. To minimize the risk, enable user-managed keys in only specific locations.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Disable Service Account Key Upload" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'iam.disableServiceAccountKeyUpload', 'booleanPolicy', true, false, 'Disable Service Account Key Upload', results);

        return callback(null, results, source);
    }
};