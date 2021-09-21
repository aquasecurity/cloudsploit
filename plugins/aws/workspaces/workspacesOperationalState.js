var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Workspaces Operational State',
    category: 'Workspaces',
    description: 'Ensure that Amazon Workspaces instances are healthy.',
    more_info: 'AWS Workspaces service inquires instances statuses by periodically sending health check requests. ' +
               'Instances which do not respond to these checks, due to some issues like blocking network ports, ' +
               'high CPU usage, etc. are considered unhealthy.',
    link: 'https://docs.aws.amazon.com/workspaces/latest/adminguide/cloudwatch-metrics.html',
    recommended_action: 'Reboot unhealthy Workspaces instances.',
    apis: ['WorkSpaces:describeWorkspaces'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);

        async.each(regions.workspaces, function(region, rcb) {
            var describeWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region]);

            if (!describeWorkspaces) {
                return rcb();
            }

            if (describeWorkspaces.err || !describeWorkspaces.data) {
                helpers.addResult(
                    results, 3, 'Unable to query for WorkSpaces information: ' + helpers.addError(describeWorkspaces), region);
                return rcb();
            }

            if (!describeWorkspaces.data.length) {
                helpers.addResult(
                    results, 0, 'No Workspaces found.', region);
                return rcb();
            }

            for (var workspace of describeWorkspaces.data) {
                if (workspace.State && workspace.State.toUpperCase() === 'UNHEALTHY') {
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
