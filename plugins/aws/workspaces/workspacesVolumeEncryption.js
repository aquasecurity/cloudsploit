var async = require("async");
var helpers = require("../../../helpers/aws");
const encryptionLevelMap = {
    sse: 1,
    awskms: 2,
    awscmk: 3,
    externalcmk: 4,
    cloudhsm: 5
};

function getEncryptionLevel(kmsKey) {
    return  kmsKey.Origin === "AWS_CLOUDHSM" ? "cloudhsm" :
            kmsKey.Origin === "EXTERNAL" ? "externalcmk" :
            kmsKey.KeyManager === "CUSTOMER" ? "awscmk" : "awskms"
}
module.exports = {
    title: "Workspaces Volume Encryption",
    category: "Workspaces",
    description: "Ensures volume encryption on Workspaces",
    more_info: "Checking the existence of volume encryption on different volumes of Workspaces",
    link: "https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
    recommended_action: "Enable encryption for all workspaces",
    apis: ["WorkSpaces:describeWorkspaces", "STS:getCallerIdentity","KMS:describeKey", "KMS:listKeys"],
    settings: {
        workspace_encryption_level: {
            name: "Workspace Minimum Default Encryption Level",
            description: "In order (lowest to highest) \
                awskms=AWS-managed KMS; \
                awscmk=Customer managed KMS; \
                externalcmk=Customer managed externally sourced KMS; \
                cloudhsm=Customer managed CloudHSM sourced KMS",
            regex: "^(awskms|awscmk|externalcmk|cloudhsm)$",
            default: "awskms",
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var desiredEncryptionLevelString = settings.workspace_encryption_level || this.settings.workspace_encryption_level.default
        if(!desiredEncryptionLevelString.match(this.settings.workspace_encryption_level.regex)) {
            helpers.addResult(results, 3, "Settings misconfigured for Workspace Volume Encryption Level.");
            return callback(null, results, source);
        }
        var desiredEncryptionLevel = encryptionLevelMap[desiredEncryptionLevelString]
        var currentEncryptionLevelString, currentEncryptionLevel

        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var accountId = helpers.addSource(cache, source, ["sts", "getCallerIdentity", acctRegion, "data"]);

        const enabledString = "Volume encryption enabled on User and Root volumes.";
        const enabledUser = "Volume encryption enabled on User volume but not on Root volume.";
        const enabledRoot = "Volume encryption enabled on Root volume but not on User volume.";
        const disabledString = "Volume encryption not enabled on any volumes.";
        const unknownStatusString = "Unable to obtain encryption status of volumes.";

        async.each(regions.workspaces, function(region, rcb){
            var listWorkspaces = helpers.addSource(cache, source, ["workspaces", "describeWorkspaces", region]);
            var listKeys = helpers.addSource(cache, source, ["kms", "listKeys", region]);

            if (!listWorkspaces) {
                return rcb()
            }

            if (!listWorkspaces.data || listWorkspaces.err) {
                helpers.addResult(results, 3, "Unable to query for WorkSpaces information: " + helpers.addError(listWorkspaces), region);
                return rcb()
            }

            if (!listKeys) {
                return rcb()
            }

            if (listKeys.err || !listKeys.data){
                helpers.addResult(results, 3, "Unable to get keys" + helpers.addError(listKeys), region);
                return rcb()
            }

            if (!listWorkspaces.data.length) {
                helpers.addResult(results, 0, "No Workspaces found.", region);
                return rcb()
            }

            for (var workspace of listWorkspaces.data) {
                var arn = "arn:" + awsOrGov + ":workspaces:" + region + ":" + accountId + ":workspace/" + workspace.WorkspaceId;
                var queryKeys = listKeys.data.find(key => key.KeyArn === workspace.VolumeEncryptionKey);

                if (!workspace.VolumeEncryptionKey){
                    helpers.addResult(results, 2, disabledString, region, arn);
                } else if (!queryKeys){
                    helpers.addResult(results, 3, `Unable to find key with key arn: ${workspace.VolumeEncryptionKey}`, region);
                } else {
                    var describeKey = helpers.addSource(cache, source, ["kms", "describeKey", region, queryKeys["KeyId"]]);
                    if (!describeKey || describeKey.err || !describeKey.data) {
                        helpers.addResult(results, 3, "Unable to query for Key information: " + helpers.addError(describeKey), region);
                        return rcb()
                    }

                    currentEncryptionLevelString = getEncryptionLevel(describeKey.data.KeyMetadata.Origin);
                    currentEncryptionLevel = encryptionLevelMap[currentEncryptionLevelString];

                    if (workspace.UserVolumeEncryptionEnabled && workspace.RootVolumeEncryptionEnabled && (desiredEncryptionLevel <= currentEncryptionLevel)){
                        helpers.addResult(results, 0, enabledString, region, arn);
                    } else  if (workspace.UserVolumeEncryptionEnabled && !workspace.RootVolumeEncryptionEnabled){
                        helpers.addResult(results, 2, enabledUser, region, arn);
                    } else if (!workspace.UserVolumeEncryptionEnabled && workspace.RootVolumeEncryptionEnabled){
                        helpers.addResult(results, 2, enabledRoot, region, arn);
                    } else if (!workspace.UserVolumeEncryptionEnabled && !workspace.RootVolumeEncryptionEnabled){
                        helpers.addResult(results, 2, disabledString, region, arn);
                    } else if (desiredEncryptionLevel >= currentEncryptionLevel){
                        helpers.addResult(results, 2, `Volume encryption is enabled at ${currentEncryptionLevelString}, which is lower than the desired ${desiredEncryptionLevelString} level.`, region, arn);
                    } else {
                        helpers.addResult(results, 3, unknownStatusString, region, arn);
                    }
                }
            }
            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}
