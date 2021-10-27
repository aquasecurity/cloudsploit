var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Compute Allowed External IPs',
    category: 'Resource Manager',
    description: 'Determine if "Define Allowed External IPs for VM Instances" constraint policy is enabled at the GCP organization level.',
    more_info: 'To reduce exposure to the internet, make sure that not all VM instances are allowed to use external IP addresses.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Define Allowed External IPs for VM Instances" constraint is enforced to allow you to define the VM instances that are allowed to use external IP addresses.',
    apis: ['organizations:list', 'organizations:listOrgPolicies'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let listOrgPolicies =  helpers.addSource(cache, source,
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

        helpers.checkOrgPolicy(orgPolicies, 'compute.vmExternalIpAccess', 'listPolicy', true, false, 'Define Allowed External IPs for VM Instances', results);

        return callback(null, results, source);
    }
};