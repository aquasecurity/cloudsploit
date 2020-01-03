var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'KMS User Separation',
    category: 'IAM',
    description: 'Ensures that no users have the KMS admin role and any one of the CryptoKey roles.',
    more_info: 'Ensuring that no users have the KMS admin role and any one of the CryptoKey roles follows separation of duties, where no user should have access to resources out of the scope of duty.',
    link: 'https://cloud.google.com/iam/docs/overview',
    recommended_action: 'Ensure that no service accounts have both the KMS admin role and any of CryptoKey roles attached.',
    apis: ['projects:getIamPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.projects, function(region, rcb){
            let iamPolicies = helpers.addSource(cache, source,
                ['projects', 'getIamPolicy', region]);

            if (!iamPolicies) return rcb();

            if (iamPolicies.err || !iamPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for IAM policies: ' + helpers.addError(iamPolicies), region);
                return rcb();
            }

            if (!iamPolicies.data.length) {
                helpers.addResult(results, 0, 'No IAM policies found', region);
                return rcb();
            }

            var iamPolicy = iamPolicies.data[0];
            var serviceAccountUsers = [];
            var notSeparated = [];
            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.role === 'roles/cloudkms.admin') {
                    serviceAccountUsers = serviceAccountUsers.concat(roleBinding.members)
                }
            });

            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.role === 'roles/cloudkms.cryptoKeyDecrypter' &&
                    roleBinding.members) {
                    notSeparated = roleBinding.members.filter(member => {
                        return (serviceAccountUsers.indexOf(member) > -1)
                    }).concat(notSeparated);
                } else if (roleBinding.role === 'roles/cloudkms.cryptoKeyEncrypter' &&
                    roleBinding.members) {
                    notSeparated = roleBinding.members.filter(member => {
                        return (serviceAccountUsers.indexOf(member) > -1)
                    }).concat(notSeparated);
                } else if (roleBinding.role === 'roles/cloudkms.cryptoKeyEncrypterDecrypter' &&
                    roleBinding.members) {
                    notSeparated = roleBinding.members.filter(member => {
                        return (serviceAccountUsers.indexOf(member) > -1)
                    }).concat(notSeparated);
                }
            });

            if (notSeparated.length) {
                notSeparated = [...new Set(notSeparated)];
                var notSeparatedStr = notSeparated.join(', ');
                helpers.addResult(results, 2,
                    `The following accounts have the KMS admin role and one or more CryptoKey roles: ${notSeparatedStr}`, region);
            } else {
                helpers.addResult(results, 0, 'No accounts have a KMS admin role or a CryptoKey key role', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};