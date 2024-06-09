var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Build Project Environment Privileged Mode',
    category: 'CodeBuild',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure that your AWS CodeBuild build project environment has privileged mode disabled.',
    more_info: 'Enabling privileged mode for CodeBuild project environments allows the build container to have elevated permissions on the host machine, which can potentially lead to security vulnerabilities and unauthorized access.',
    recommended_action: 'Modify CodeBuild build project and disable environment privileged mode.',
    link: 'https://docs.aws.amazon.com/codebuild/latest/userguide/change-project-console.html',
    apis: ['CodeBuild:listProjects', 'CodeBuild:batchGetProjects','STS:GetCallerIdentity'],
    realtime_triggers: ['codebuild:CreateProject', 'codebuild:UpdateProject','codebuild:DeleteProject'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['STS', 'GetCallerIdentity', acctRegion, 'data']);

        async.each(regions.codebuild, function(region, rcb){
            var listProjects = helpers.addSource(cache, source,
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
                    if(batchGetProjects.data.projects[0] && 
                       batchGetProjects.data.projects[0].environment &&
                       batchGetProjects.data.projects[0].environment.privilegedMode) {
                        helpers.addResult(results, 2,
                           'CodeBuild project environment has privileged mode enabled', region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'CodeBuild project environment has privileged mode disabled', region, resource);
                    }
                }
                
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 