
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Trusted Image Projects',
    category: 'Resource Manager',
    description: 'Determine if "Define Trusted Image Projects" constraint policy is enforces at the GCP organization level.',
    more_info: 'Enforcing the "Define Trusted Image Projects" allows you to restrict disk image access and ensure that your project members can only create boot disks from trusted images.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Define Trusted Image Projects" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'compute.trustedImageProjects', 'listPolicy', true, false, 'Define Trusted Image Projects', results);

        return callback(null, results, source);
    }
};