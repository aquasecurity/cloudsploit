var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Enforce Restrict Authorized Networks',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Restrict Authorized Networks on Cloud SQL instances" policy is enforced at the GCP organization level.',
    more_info: 'Enforcing "Restrict Authorized Networks on Cloud SQL instances" organization policy, restricts adding authorized networks for unproxied database access to Cloud SQL instances.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Restrict Authorized Networks on Cloud SQL instances" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'sql.restrictAuthorizedNetworks', 'booleanPolicy', true, false, 'Restrict Authorized Networks on Cloud SQL instances', results);

        return callback(null, results, source);
    }
};