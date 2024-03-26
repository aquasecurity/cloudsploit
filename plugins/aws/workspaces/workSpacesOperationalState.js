var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'WorkSpaces Operational State',
    category: 'WorkSpaces',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensure that the AWS WorkSpaces instances are healthy.',
    more_info: 'The AWS WorkSpaces service periodically sends status requests to the WorkSpaces instances. An instance is pronounced unhealthy when it fails to respond to these HealthCheck requests.',
    recommended_action: 'Troubleshoot the workspace when state is unhealthy.',
    link: 'https://docs.aws.amazon.com/workspaces/latest/adminguide/workspace-maintenance.html',
    apis: ['WorkSpaces:describeWorkspaces'],
    realtime_triggers: ['workspaces:CreateWorkspaces','workspaces:DeleteWorkspaces'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.workspaces, function(region, rcb){
            var listWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region]);

            if (!listWorkspaces) {
                return rcb();
            }

            if (!listWorkspaces || listWorkspaces.err || !listWorkspaces.data) {
                helpers.addResult(results, 3,
                    'Unable to list Workspaces: ' + helpers.addError(listWorkspaces), region);
                return rcb();
            }
            
            if (!listWorkspaces.data.length) {
                helpers.addResult(results, 0,
                    'No WorkSpaces instances found', region);
                return rcb();
            }
            listWorkspaces.data.forEach(workspace => {
                if (!workspace.WorkspaceId) return;

                let resource = `arn:${awsOrGov}:region:${region}:${accountId}:worskpace/${workspace.WorkspaceId}`;

                if (workspace.State === 'UNHEALTHY') {
                    helpers.addResult(results, 2,
                        'The workspace is not operational', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'WorkSpace is operational', region, resource);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
