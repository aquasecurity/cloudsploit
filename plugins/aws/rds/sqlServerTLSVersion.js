var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SQL Server TLS Version',
    category: 'RDS',
    description: 'Ensures RDS SQL Servers do not allow outdated TLS certificate versions',
    more_info: 'TLS 1.2 or higher should be used for all TLS connections to RDS. A parameter group can be used to enforce this connection type.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2020/07/amazon-rds-for-sql-server-supports-disabling-old-versions-of-tls-and-ciphers/',
    recommended_action: 'Create a parameter group that contains the TLS version restriction and limit access to TLS 1.2 or higher',
    apis: ['RDS:describeDBParameterGroups', 'RDS:describeDBParameters'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        async.each(regions.rds, function(region, rcb){
            var describeDBParameterGroups = helpers.addSource(cache, source,
                ['rds', 'describeDBParameterGroups', region]);

            if (!describeDBParameterGroups) return rcb();
            
            if (describeDBParameterGroups.err || !describeDBParameterGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for parameter groups: ' + helpers.addError(describeDBParameterGroups), region);
                return rcb();
            }

            if (!describeDBParameterGroups.data.length) {
                helpers.addResult(results, 0, 'No parameter groups found', region);
                return rcb();
            }

            var sqlFound = false;

            async.each(describeDBParameterGroups.data, function(group, paramcb){
                if (!group.DBParameterGroupName) return paramcb();
                
                var resource = group.DBParameterGroupArn;

                if (group.DBParameterGroupFamily && !group.DBParameterGroupFamily.startsWith('sqlserver')) return paramcb();
                sqlFound = true;
                
                var parameters = helpers.addSource(cache, source,
                    ['rds', 'describeDBParameters', region, group.DBParameterGroupName]);

                if (!parameters || parameters.err || !parameters.data){
                    helpers.addResult(results, 3,
                        'Unable to query for parameters: ' + helpers.addError(parameters),
                        region, resource);
                    return paramcb();
                }

                if (!parameters.data.Parameters || !parameters.data.Parameters.length) {
                    helpers.addResult(results, 2, 'No parameters found for group', region, resource);
                    return paramcb();
                }

                var tls10 = null;
                var tls11 = null;
                var tls12 = null;

                for (var param in parameters.data.Parameters) {
                    if (parameters.data.Parameters[param] &&
                        parameters.data.Parameters[param].ParameterName &&
                        parameters.data.Parameters[param].ParameterName === 'rds.tls10') {
                        
                        tls10 = parameters.data.Parameters[param].ParameterValue;
                    }
                    else if (parameters.data.Parameters[param] &&
                        parameters.data.Parameters[param].ParameterName &&
                        parameters.data.Parameters[param].ParameterName === 'rds.tls11') {
                        
                        tls11 = parameters.data.Parameters[param].ParameterValue;
                    }
                    else if (parameters.data.Parameters[param] &&
                        parameters.data.Parameters[param].ParameterName &&
                        parameters.data.Parameters[param].ParameterName === 'rds.tls12') {
                        
                        tls12 = parameters.data.Parameters[param].ParameterValue;
                    }
                    if (!tls10 || !tls11 || !tls12) continue;
                }

                if (tls10 === 'disabled' && tls11 === 'disabled' && tls12 != 'disabled') {
                    helpers.addResult(results, 0,
                        'DB parameter group ' + (group.DBParameterGroupName) + ' uses TLS 1.2',
                        region, resource);
                }
                else {
                    helpers.addResult(results, 2,
                        'DB parameter group ' + (group.DBParameterGroupName) + ' does not require TLS 1.2',
                        region, resource);
                }

                paramcb();
            });

            if (!sqlFound) {
                helpers.addResult(results, 0, 'No DB parameter groups for SQL servers found', region);
            }
            
            rcb();
        
        }, function(){
            callback(null, results, source);
        });
    }
};
