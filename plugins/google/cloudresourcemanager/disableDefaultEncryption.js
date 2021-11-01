var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disable Default Encryption Creation',
    category: 'Resource Manager',
    description: 'Determine if "Restrict Default Google-Managed Encryption for Cloud SQL Instances" is enforced on the GCP organization level.',
    more_info: 'Google-managed encryption keys for Cloud SQL database instances to enforce the use of Customer-Managed Keys (CMKs) in order to have complete control over database encryption/decryption process.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Restrict Default Google-Managed Encryption for Cloud SQL Instances" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'sql.disableDefaultEncryptionCreation', 'booleanPolicy', true, false, 'Restrict Default Google-Managed Encryption for Cloud SQL Instances', results);

        return callback(null, results, source);
    }
};