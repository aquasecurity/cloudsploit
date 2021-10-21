var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Service Account Token Creator',
    category: 'IAM',
    description: 'Ensures that no users have the Service Account Token Creator role.',
    more_info: 'For best security practices, IAM users should not have Service Account Token Creator role.',
    link: 'https://cloud.google.com/iam/docs/overview',
    recommended_action: 'Ensure that no IAM user have Service Account Token Creator Role at GCP project level.',
    apis: ['projects:getIamPolicy', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.projects, function(region, rcb) {
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

            var serviceAccountExists = false;

            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.role === 'roles/iam.serviceAccountTokenCreator') {
                    serviceAccountExists = true;
                    roleBinding.members.forEach(member => {
                        let accountName = (member.includes(':')) ? member.split(':')[1] : member;
                        let memberType = member.startsWith('serviceAccount') ? 'serviceAccounts' : 'users';
                        let resource = helpers.createResourceName(memberType, accountName, project);
                        helpers.addResult(results, 2,
                            'The account has a service account token creator role', region, resource);
                    });
                }
            });

            if (!serviceAccountExists) {
                helpers.addResult(results, 0, 'No accounts have service account token creator roles', region);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};