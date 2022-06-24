var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Location-Based Service Restriction',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Resource Location Restriction" is enforced on the GCP organization level.',
    more_info: 'Enforcing the "Resource Location Restriction" constraint allows you to define the locations where your cloud resources can be created.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Resource Location Restriction" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'gcp.resourceLocations', 'listPolicy', true, false, 'Resource Location Restriction', results);

        return callback(null, results, source);
    }
};