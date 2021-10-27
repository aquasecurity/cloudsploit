var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Enforce Require OS Login',
    category: 'Resource Manager',
    description: 'Determine if "Require OS Login" policy is enforced at the GCP organization level.',
    more_info: 'Enabling OS Login at project level will ensure that the SSH keys being used to access your VM instances are mapped with Cloud IAM users.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Require OS Login" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'compute.requireOsLogin', 'booleanPolicy', true, false, 'Require OS Login', results);

        return callback(null, results, source);
    }
};