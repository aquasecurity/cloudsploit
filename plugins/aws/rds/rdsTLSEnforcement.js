var async = require("async");
var helpers = require("../../../helpers/aws");

module.exports = {
    title: "RDS TLS Enforcement Requirement",
    category: "RDS",
    description: "Ensures enforced TLS on Databases",
    more_info: "Checking if the existing parameter groups on RDS databases is using TLS.",
    link: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html",
    recommended_action: "Enable TLS on RDS database.",
    apis: ["RDS:describeDBInstances","RDS:describeDBParameterGroups", "RDS:describeDBParameters", "STS:getCallerIdentity"],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var parameterMappings = {
            "mysql": "require_secure_transport",
            "sqlserver-ex": "rds.force_ssl",
            "sqlserver-ee": "rds.force_ssl",
            "sqlserver-se": "rds.force_ssl",
            "sqlserver-web": "rds.force_ssl",
            "postgres": "rds.force_ssl"
        };

        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.rds, function(region, rcb){
            var listDBInstances = helpers.addSource(cache, source, ["rds", "describeDBInstances", region]);
            if (!listDBInstances) {
                return rcb()
            }

            if (listDBInstances.err) {
                helpers.addResult(results, 3, "Unable to query for RDS information: " + helpers.addError(listDBInstances), region);
                return rcb()
            }

            if (!listDBInstances.data.length) {
                helpers.addResult(results, 0, "No RDS Databases found", region);
                return rcb()
            }

            for (var instance of listDBInstances.data) {
                var arn = instance.DBInstanceArn;
                var tlsEnforced = false;
                var engineName = instance.Engine;
                if (!parameterMappings[engineName]) {
                    helpers.addResult(results, 0, `TLS Enforcement is not supported on the ${instance.DBInstanceIdentifier} database with ${engineName} engine.`, region, arn);
                } else {
                    for (var parameterGroup of instance.DBParameterGroups) {
                        var listDBParameters = helpers.addSource(cache, source,
                            ["rds", "describeDBParameters", region, parameterGroup.DBParameterGroupName]
                        );
                        if (listDBParameters.err || !listDBParameters.data || !listDBParameters) {
                            helpers.addResult(results, 3, `Unable to query for parameters on Parameter Group: ${parameterGroup.DBParameterGroupName}.` + helpers.addError(listDBParameters), region, arn);
                        } else {
                            var query = listDBParameters.data.Parameters.find(directory => directory.ParameterName === parameterMappings[engineName]);
                            if (!query) {
                                tlsEnforced = false;
                                helpers.addResult(results, 3, `Unable to find Parameter: ${parameterMappings[engineName]} for ${instance.DBInstanceIdentifier} database.`, region, arn);
                                break;
                            } else if (query.ParameterValue === "1") {
                                tlsEnforced = true;
                            } else {
                                tlsEnforced = false;
                                helpers.addResult(results, 2, `TLS is not enforced on the ${instance.DBInstanceIdentifier} database.`, region, arn);
                                break;
                            }
                        }
                    }
                }

                if (tlsEnforced) {
                    helpers.addResult(results, 0, `TLS is enforced on the ${instance.DBInstanceIdentifier} database.`, region, arn);
                }
            }
            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}
