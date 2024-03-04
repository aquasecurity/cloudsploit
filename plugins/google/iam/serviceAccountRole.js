var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Service Account Role',
    category: 'IAM',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensure no Service Account exists without any associated role.',
    more_info: 'Service Account acts as identity for the applications to authenticate to Google cloud platform. It is a security best practice to always have roles associated with the user managed Service Accounts.',
    link: 'https://cloud.google.com/iam/docs/service-account-permissionsw',
    recommended_action: 'Ensure that no service accounts exists without an associated role.',
    apis: ['projects:getIamPolicy', 'serviceAccounts:list'],
    realtime_triggers: ['iam.IAMPolicy.SetIamPolicy', 'iam.admin.CreateServiceAccount' , 'iam.admin.DeleteServiceAccount'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.projects, function(region, rcb){
            let iamPolicies = helpers.addSource(cache, source,
                ['projects', 'getIamPolicy', region]);

            if (!iamPolicies) return rcb();

            if (iamPolicies.err || !iamPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for IAM Policies', region, null, null, iamPolicies.err);
                return rcb();
            }

            if (!iamPolicies.data.length) {
                helpers.addResult(results, 0, 'No IAM policies found.', region);
                return rcb();
            }

            let serviceAccounts = helpers.addSource(cache, source,
                ['serviceAccounts', 'list', region]);

            if (!serviceAccounts) return rcb();

            if (serviceAccounts.err || !serviceAccounts.data) {
                helpers.addResult(results, 3, 'Unable to query for service accounts', region, null, null, iamPolicies.err);
                return rcb();
            }

            if (!serviceAccounts.data.length) {
                helpers.addResult(results, 0, 'No service accounts found.', region);
                return rcb();
            }

            var iamPolicy = iamPolicies.data[0];

            serviceAccounts.data.forEach(serviceAccount => {
                if (iamPolicy && iamPolicy.bindings && iamPolicy.bindings.length
                    && iamPolicy.bindings.find(binding => binding.members
                        && binding.members.find(member => member.includes(serviceAccount.email)))
                ) {
                    helpers.addResult(results, 0,
                        'Service Account has one or more roles associated with it', region, serviceAccount.name);
                } else {
                    helpers.addResult(results, 2,
                        'Service Account does not have any role associated with it', region, serviceAccount.name);
                }
    
            });
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};