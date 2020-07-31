var async = require("async");
var helpers = require("../../../helpers/aws");

module.exports = {
    title: "Workspaces IP Access Control",
    category: "Workspaces",
    description: "Ensures enforced IP Access Control on Workspaces",
    more_info: "Checking the existence of IP Access control on Workspaces and no open IP to any Workspaces",
    link: "https://docs.aws.amazon.com/workspaces/latest/adminguide/amazon-workspaces-ip-access-control-groups.html",
    recommended_action: "Enable proper IP Access Controls for all workspaces",
    apis: ["WorkSpaces:describeWorkspaces", "WorkSpaces:describeWorkspaceDirectories", "WorkSpaces:describeIpGroups", "STS:getCallerIdentity"],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var accountId = helpers.addSource(cache, source, ["sts", "getCallerIdentity", acctRegion, "data"]);

        async.each(regions.workspaces, function(region, ipcontrol){
            var listWorkspaces = helpers.addSource(cache, source, ["workspaces", "describeWorkspaces", region, "data"]);
            var listDirectories = helpers.addSource(cache, source, ["workspaces", "describeWorkspaceDirectories", region, "data"]);
            var listIPGroups = helpers.addSource(cache, source, ["workspaces", "describeIpGroups", region, "data"]);

            if (!listWorkspaces) {
                return callback(null, results, source)
            }

            if (listWorkspaces.err) {
                helpers.addResult(
                    results, 3, "Unable to query for WorkSpaces information: " + helpers.addError(listWorkspaces), region
                );
            }

            if (!listWorkspaces.length) {
                helpers.addResult(
                    results, 0, "No Workspaces found.", region
                );
            }

            for (var i in listWorkspaces) {
                var workspace = listWorkspaces[i];
                var arn = "arn:" + awsOrGov + ":workspaces:" + region + ":" + accountId + ":workspace/" + workspace.WorkspaceId;

                if (!("DirectoryId" in workspace)){
                    helpers.addResult(
                        results, 2, "IP Access Control not enabled.", region, arn
                    );
                }

                if (workspace){
                    var workspaceDirectory = listDirectories.find(directory => directory.DirectoryId === workspace.DirectoryId);

                    if (!("ipGroupIds" in workspaceDirectory)){
                        helpers.addResult(
                            results, 2, "IP Access Control not enabled.", region, arn
                        );
                    }

                    if ("ipGroupIds" in workspaceDirectory){
                        for (var j in workspaceDirectory.ipGroupIds){
                            var ipGroup = listIPGroups.find(o => o.groupId === workspaceDirectory.ipGroupIds[j]);

                            if (!("userRules" in ipGroup)){
                                helpers.addResult(
                                    results, 2, "IP Access Control not enabled.", region, arn
                                );
                            }

                            if ("userRules" in ipGroup){
                                var queryIPGroup = ipGroup.userRules.find(o => o.ipRule === "0.0.0.0/0");

                                if (queryIPGroup){
                                    helpers.addResult(
                                        results, 2, "IP range 0.0.0.0/0 is enabled.", region, arn
                                    );
                                    break;
                                } else {
                                    helpers.addResult(
                                        results, 0, "IP Access Control enabled.", region, arn
                                    );
                                }
                            }
                        }
                    }
                }
            }

            ipcontrol();

        }, function(){
            callback(null, results, source);
        });

        return callback(null, results, source);
    }

}