var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disable Serial Port Access',
    category: 'Resource Manager',
    description: 'Determine if "Disable VM serial port access" policy is enforced at the GCP organization level.',
    more_info: 'For security purposes, ensure that serial port access to your VM instances is disabled.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Disable VM serial port access" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'compute.disableSerialPortAccess', 'booleanPolicy', true, false, 'Disable VM serial port access', results);

        return callback(null, results, source);
    }
};