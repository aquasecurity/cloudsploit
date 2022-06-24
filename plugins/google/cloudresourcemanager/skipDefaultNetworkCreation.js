
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Skip Default Network Creation',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Skip Default Network Creation" constraint policy is enforces at the GCP organization level.',
    more_info: 'Enforcing the "Skip Default Network Creation" disables the creation of default VPC network on project creation which is recommended if you want to keep some parts of your network private.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Skip Default Network Creation" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'compute.skipDefaultNetworkCreation', 'booleanPolicy', true, false, 'Skip Default Network Creation', results);

        return callback(null, results, source);
    }
};