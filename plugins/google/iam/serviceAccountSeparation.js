var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Service Account Separation',
    category: 'IAM',
    description: 'Ensures that no users have both the Service Account User and Service Account Admin role.',
    more_info: 'Ensuring that no users have both roles follows separation of duties, where no user should have access to resources out of the scope of duty.',
    link: 'https://cloud.google.com/iam/docs/overview',
    recommended_action: 'Ensure that no service accounts have both the Service Account User and Service Account Admin role attached.',
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
                helpers.addResult(results, 3, 'Unable to query for IAM policies', region, null, null, iamPolicies.err);
                return rcb();
            }

            if (!iamPolicies.data.length) {
                helpers.addResult(results, 0, 'no IAM policies found', region);
                return rcb();
            }

            var iamPolicy = iamPolicies.data[0];
            var serviceAccountUsers = [];
            var notSeparated = {};
            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.role === 'roles/iam.serviceAccountUser') {
                    serviceAccountUsers = serviceAccountUsers.concat(roleBinding.members)
                }
            });

            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.role === 'roles/iam.serviceAccountAdmin' &&
                    roleBinding.members) {
                    notSeparated = roleBinding.members.filter(member => {
                        return (serviceAccountUsers.indexOf(member) > -1)
                    });

                    if (notSeparated && notSeparated.length) {
                        notSeparated.forEach(member => {
                            helpers.addResult(results, 2,
                                'The account has both the service account user and admin role', region, member);
                        })
                    }
                }
            });

            if (!notSeparated.length) {
                helpers.addResult(results, 0, 'No accounts have both the service account user and admin roles', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};