var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Service Account Admin',
    category: 'IAM',
    description: 'Ensures that user managed service accounts do not have any admin, owner, or write privileges.',
    more_info: 'Service accounts are primarily used for API access to Google. It is recommended to not use admin access for service accounts.',
    link: 'https://cloud.google.com/iam/docs/overview',
    recommended_action: 'Ensure that no service accounts have admin, owner, or write privileges.',
    apis: ['projects:get','projects:getIamPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.projects, function(region, rcb){
            let iamPolicies = helpers.addSource(cache, source,
                ['projects', 'getIamPolicy', region]);

            let project = helpers.addSource(cache, source,
                ['projects', 'get', region]);

            if (!iamPolicies) return rcb();

            if (iamPolicies.err || !iamPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for IAM Policies: ' + helpers.addError(iamPolicies), region);
                return rcb();
            }

            if (!iamPolicies.data.length) {
                helpers.addResult(results, 0, 'No IAM policies found.', region);
                return rcb();
            }

            if (project && project.data && project.data.length) {
                var projectName = project.data[0].name;
            }

            var serviceAccountCheck = `${projectName}.iam.gserviceaccount.com`;
            var serviceAccountAdmins = [];
            var serviceAccountOwners = [];
            var serviceAccountEditors = [];
            var iamPolicy = iamPolicies.data[0];

            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.role) {
                    var role = roleBinding.role.split('.');
                    if (role.length > 1) {
                        role = role[1];
                    }
                    if (role === 'admin') {
                        roleBinding.members.forEach(member => {
                            var memberStrArr = member.split('@');
                            if (memberStrArr[1] === serviceAccountCheck) {
                                serviceAccountAdmins.push(member);
                            }
                        })
                    } else if (roleBinding.role === 'roles/editor') {
                        roleBinding.members.forEach(member => {
                            var memberStrArr = member.split('@');
                            if (memberStrArr[1] === serviceAccountCheck) {
                                serviceAccountEditors.push(member);
                            }
                        })
                    } else if (roleBinding.role === 'roles/owner') {
                        roleBinding.members.forEach(member => {
                            var memberStrArr = member.split('@');
                            if (memberStrArr[1] === serviceAccountCheck) {
                                serviceAccountOwners.push(member);
                            }
                        })
                    }
                }
            });
            var serviceAccountExists = false;

            if (serviceAccountAdmins.length) {
                serviceAccountExists = true;
                var serviceAccountAdminsStr = serviceAccountAdmins.join(', ');
                helpers.addResult(results, 2,
                    `The following service accounts have admin privileges: ${serviceAccountAdminsStr}`, region);
            }

            if (serviceAccountOwners.length) {
                serviceAccountExists = true;
                var serviceAccountOwnersStr = serviceAccountOwners.join(', ');
                helpers.addResult(results, 2,
                    `The following service accounts have owner privileges: ${serviceAccountOwnersStr}`, region);
            }

            if (serviceAccountEditors.length) {
                serviceAccountExists = true;
                var serviceAccountEditorsStr = serviceAccountEditors.join(', ');
                helpers.addResult(results, 2,
                    `The following service accounts have editor privileges: ${serviceAccountEditorsStr}`, region);
            }

            if (!serviceAccountExists) {
                helpers.addResult(results, 0, 'All service accounts have least access', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};