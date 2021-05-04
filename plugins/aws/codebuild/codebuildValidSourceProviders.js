var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CodeBuild Valid Source Providers',
    category: 'CodeBuild',
    description: 'Ensure that CodeBuild projects are using only valid source providers.',
    more_info: 'CodeBuild should use only desired source providers in order to follow your organizations\'s security and compliance requirements.',
    link: 'https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectSource.html',
    recommended_action: 'Edit CodeBuild project source provider information and remove disallowed source providers',
    apis: ['CodeBuild:listProjects', 'CodeBuild:batchGetProjects', 'STS:getCallerIdentity'],
    settings: {
        codebuild_disallowed_source_providers: {
            name: 'CodeBuild Disallowed Source Providers',
            description: 'A comma-separated list of source providers which should not be used',
            regex: '^((bitbucket|codecommit|codepipeline|github|github_enterprise|s3|),? ?){1,5}$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            codebuild_disallowed_source_providers: settings.codebuild_disallowed_source_providers || this.settings.codebuild_disallowed_source_providers.default
        };

        if (!config.codebuild_disallowed_source_providers.length) return callback(null, results, source);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.codebuild, function(region, rcb){
            var listProjects = helpers.addSource(cache, source, ['codebuild', 'listProjects', region]);

            if (!listProjects) return rcb();

            if (listProjects.err || !listProjects.data) {
                helpers.addResult(results, 3, `Unable to query CodeBuild projects: ${helpers.addError(listProjects)}`, region);
                return rcb();
            }

            if (!listProjects.data.length) {
                helpers.addResult(results, 0, 'No CodeBuild projects found', region);
                return rcb();
            }

            async.each(listProjects.data, function(project, cb) {
                var resource = `arn:${awsOrGov}:codebuild:${region}:${accountId}:project/${project}`;

                var batchGetProjects = helpers.addSource(cache, source, ['codebuild', 'batchGetProjects', region, project]);

                if (!batchGetProjects || batchGetProjects.err ||
                    !batchGetProjects.data || !batchGetProjects.data.projects || !batchGetProjects.data.projects.length) {
                    helpers.addResult(results, 3,
                        `Unable to query CodeBuild project: ${helpers.addError(batchGetProjects)}`, region, resource);
                    return cb();
                }

                var invalidSources = [];
                if (batchGetProjects.data.projects[0].source &&
                    batchGetProjects.data.projects[0].source.type &&
                    config.codebuild_disallowed_source_providers.includes(batchGetProjects.data.projects[0].source.type.toLowerCase())) 
                    invalidSources.push(batchGetProjects.data.projects[0].source.type.toLowerCase());
                
                if (batchGetProjects.data.projects[0].secondarySources &&
                    batchGetProjects.data.projects[0].secondarySources.length) {
                    for (let source of batchGetProjects.data.projects[0].secondarySources) {
                        var sourceLower = source.type.toLowerCase();
                        if (config.codebuild_disallowed_source_providers.includes(sourceLower) && !invalidSources.includes(sourceLower)) invalidSources.push(sourceLower);
                    }
                }

                if (invalidSources.length) {
                    helpers.addResult(results, 2,
                        `CodeBuild project is using these disallowed source providers: ${invalidSources.join(', ')}`, region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'CodeBuild project is using allowed source providers', region, resource);
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};