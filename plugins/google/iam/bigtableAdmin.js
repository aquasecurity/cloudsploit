var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Bigtable Admin',
    category: 'IAM',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensure that there are no IAM Users with Bigtable Administrator role at the project level.',
    more_info: 'The pre-defined role "Bigtable Administrator" grants full permission over Bigtable resources and its data. As a best practice, avoid giving access to this role at the project level; instead, grant specific Bigtable related permissions to IAM members.',
    link: 'https://cloud.google.com/iam/docs/overview',
    recommended_action: 'Ensure that no IAM member has the pre-defined Bigtable Administrator role.',
    apis: ['projects:getIamPolicy'],
    realtime_triggers: ['iam.IAMPolicy.SetIamPolicy'],

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
            let notFoundMessage = 'No accounts have the pre-defined Bigtable Admin role';

            helpers.checkIAMRole(iamPolicy, ['roles/bigtable.admin'], region, results, project, notFoundMessage);
            
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};