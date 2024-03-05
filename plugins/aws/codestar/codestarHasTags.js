var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CodeStar Has Tags',
    category: 'CodeStar',
    domain: 'Application Integration',
    severity: 'Low',
    description: 'Ensures that CodeStar projects has tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/codestar/latest/userguide/working-with-project-tags.html',
    recommended_action: 'Modify CodeStar Project and add tags.',
    apis: ['CodeStar:listProjects','ResourceGroupsTaggingAPI:getResources'],
    realtime_triggers: ['codestar:CreateProject','codestar:DeleteProject', 'codestar:tagresource', 'codestar:untagresource'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.codestar, function(region, rcb){
            var listProjects = helpers.addSource(cache, source, ['codestar', 'listProjects', region]);

            if (!listProjects) return rcb();

            if (listProjects.err || !listProjects.data) {
                helpers.addResult(results, 3, `Unable to query CodeStar projects: ${helpers.addError(listProjects)}`, region);
                return rcb();
            }

            if (!listProjects.data.length) {
                helpers.addResult(results, 0, 'No CodeStar projects found', region);
                return rcb();
            }

            const arnList = [];
            for (let project of listProjects.data){
                arnList.push(project.projectArn);
            }

            helpers.checkTags(cache, 'CodeStar', arnList, region, results, settings);
            return rcb();

        }, function(){
            callback(null, results, source);
        });
    }
}; 
