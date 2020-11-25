var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Corporate Emails Only',
    category: 'IAM',
    description: 'Ensures that no users are using their Gmail accounts for access to GCP.',
    more_info: 'Gmail accounts are personally created and are not controlled by organizations. Fully managed accounts are recommended for increased visibility, auditing and control over access to resources.',
    link: 'https://cloud.google.com/iam/docs/overview',
    recommended_action: 'Ensure that no users are actively using their Gmail accounts to access GCP.',
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
            var gmailUsers = [];
            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.members && roleBinding.members.length) {
                    roleBinding.members.forEach(member => {
                        var emailArr = member.split('@');
                        var provider = emailArr[1].split('.');
                        if (provider[0] === 'gmail' && (gmailUsers.indexOf(member) === -1)) {
                            gmailUsers.push(member);
                        }
                    })
                }
            });

            if (gmailUsers.length) {
                var gmailUsersStr = gmailUsers.join(', ');
                helpers.addResult(results, 2,
                    `The following accounts are using Gmail login credentials: ${gmailUsersStr}`, region);
            } else {
                helpers.addResult(results, 0, 'No accounts are using Gmail login credentials', region);
            }


            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};