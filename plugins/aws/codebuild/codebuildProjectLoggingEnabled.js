var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CodeBuild Project Logging Enabled',
    category: 'CodeBuild',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure that your AWS CodeBuild build project has S3 or Cloudwatch logs enabled.',
    more_info: 'Monitoring AWS CodeBuild projects helps maintaining the reliability, availability, and performance of the resource. It helps to easily debug multi-point failure and potential incidents.',
    recommended_action: 'Ensure that CodeBuild project has logging enabled.',
    link: 'https://docs.aws.amazon.com/codebuild/latest/userguide/monitoring-builds.html',
    apis: ['CodeBuild:listProjects', 'CodeBuild:batchGetProjects', 'STS:GetCallerIdentity'],
    realtime_triggers: ['codebuild:CreateProject', 'codebuild:UpdateProject', 'codebuild:DeleteProject'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['STS', 'GetCallerIdentity', acctRegion, 'data']);

        async.each(regions.codebuild, function(region, rcb) {
            var listProjects =helpers.addSource(cache, source,
                ['codebuild', 'listProjects', region]);

            if (!listProjects) return rcb();

            if (listProjects.err || !listProjects.data) {
                helpers.addResult(results, 3,
                    `Unable to list CodeBuild projects: ${helpers.addError(listProjects)}`, region);
                return rcb();
            }

            if (!listProjects.data.length) {
                helpers.addResult(results, 0,
                    'No CodeBuild projects found', region);
                return rcb();
            }

            for (let project of listProjects.data) {
                var resource = `arn:${awsOrGov}:codebuild:${region}:${accountId}:project/${project}`;

                let batchGetProjects = helpers.addSource(cache, source,
                    ['codebuild', 'batchGetProjects', region, project]);

                if (!batchGetProjects || batchGetProjects.err || !batchGetProjects.data ||
                    !batchGetProjects.data.projects || !batchGetProjects.data.projects.length) {
                    helpers.addResult(results, 3,
                        `Unable to query CodeBuild project: ${helpers.addError(batchGetProjects)}`, region, resource);
                } else {

                    var found = (batchGetProjects.data.projects[0] && 
                        batchGetProjects.data.projects[0].logsConfig &&
                        Object.values(batchGetProjects.data.projects[0].logsConfig).some(log => log.status === 'ENABLED')) || false;

                    if (found) {
                        helpers.addResult(results, 0,
                            'CodeBuild project has logging enabled', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'CodeBuild project does not have logging enabled', region, resource);
                    }
                }

            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
}; 