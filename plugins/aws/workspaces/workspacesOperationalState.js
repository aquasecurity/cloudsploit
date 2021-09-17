var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Workspaces Operational State',
    category: 'Workspaces',
    description: 'Ensures instances are healthy on Workspaces',
    more_info: 'Checking the workspaces instances state are healthy or not?',
    link: 'https://docs.aws.amazon.com/workspaces/latest/adminguide/cloudwatch-metrics.html',
    recommended_action: 'Ensures that workspaces instance is respond to service health checks',
    apis: ['WorkSpaces:describeWorkspaces'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);

        async.each(regions.workspaces, function(region, rcb) {
            var listWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region, 'data']);

            if (!listWorkspaces) {
                return rcb();
            }

            if (listWorkspaces.err) {
                helpers.addResult(
                    results, 3, 'Unable to query for WorkSpaces information: ' + helpers.addError(listWorkspaces), region);
                return rcb();
            }

            if (!listWorkspaces.length) {
                helpers.addResult(
                    results, 0, 'No Workspaces found.', region);
                return rcb();
            }

            for (var workspace of listWorkspaces) {
                if (workspace.State && workspace.State === 'UNHEALTHY') {
                    helpers.addResult(results, 2, 'Workspaces instance is '+ workspace.State, region);
                } else {
                    helpers.addResult(results, 0, 'Workspaces instance is '+ workspace.State, region);
                }
            }

            return rcb();

        }, function(){
            callback(null, results, source);
        });
    }
};
