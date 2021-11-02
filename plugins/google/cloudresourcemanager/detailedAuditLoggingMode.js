var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Detailed Audit Logging Mode',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Detailed Audit Logging Mode" policy is configured at the GCP organization level.',
    more_info: 'Detailed Audit Logging Mode is highly encouraged in coordination with Bucket Lock when seeking compliances such as SEC Rule 17a-4(f), CFTC Rule 1.31(c)-(d), and FINRA Rule 4511(c).',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Detailed Audit Logging Mode" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'gcp.detailedAuditLoggingMode', 'booleanPolicy', true, false, 'Detailed Audit Logging Mode', results);

        return callback(null, results, source);
    }
};