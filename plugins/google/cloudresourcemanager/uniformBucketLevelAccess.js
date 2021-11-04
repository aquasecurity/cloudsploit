var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Enforce Uniform Bucket-Level Access',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Enforce uniform bucket-level access" policy is enabled at the GCP organization level.',
    more_info: 'Enforcing Uniform Bucket Level Access ensures that access is granted exclusively through Cloud IAM service which is more efficient and secure.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Enforce uniform bucket-level access" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'storage.uniformBucketLevelAccess', 'booleanPolicy', true, false, 'Enforce uniform bucket-level access', results);

        return callback(null, results, source);
    }
};