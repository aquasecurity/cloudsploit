var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Member Admin',
    category: 'IAM',
    description: 'Ensure that IAM members do not use primitive roles such as owner, editor or viewer.',
    more_info: 'For best security practices, use only predefined IAM roles and do not use primitive roles to prevent any unauthorized access to your resources.',
    link: 'https://cloud.google.com/iam/docs/overview',
    recommended_action: 'Ensure that no IAM member has a primitive role.',
    apis: ['projects:getIamPolicy', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.projects, function(region, rcb){
            let iamPolicies = helpers.addSource(cache, source,
                ['projects', 'getIamPolicy', region]);

            if (!iamPolicies) return rcb();

            if (iamPolicies.err || !iamPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for IAM policies', region, null, null, iamPolicies.err);
                return rcb();
            }

            if (!iamPolicies.data.length) {
                helpers.addResult(results, 0, 'No IAM policies found', region);
                return rcb();
            }

            var iamPolicy = iamPolicies.data[0];
            var primitiveRoleExists = false;

            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.role && ['roles/editor', 'roles/viewer', 'roles/owner'].includes(roleBinding.role)) {
                    primitiveRoleExists = true;
                    roleBinding.members.forEach(member => {
                        let accountName = (member.includes(':')) ? member.split(':')[1] : member;
                        let memberType = member.startsWith('serviceAccount') ? 'serviceAccounts' : 'users';
                        let resource = helpers.createResourceName(memberType, accountName, project);
                        helpers.addResult(results, 2,
                            `The account has the primitive role: ${roleBinding.role}`, region, resource);
                    });
                }
            });

            if (!primitiveRoleExists) {
                helpers.addResult(results, 0, 'No accounts have primitive roles', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};