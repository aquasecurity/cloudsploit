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
                    'Unable to query for parameter groups: ' + helpers.addError(describeDBParameterGroups));
                return rcb();
            }

            if (!describeDBParameterGroups.data.length) {
                helpers.addResult(results, 0, 'No parameter groups found');
                return rcb();
            }

            async.each(describeDBParameterGroups.data, function(group, paramcb){
                if (!group.DBParameterGroupName) return paramcb();
                
                var resource = group.DBParameterGroupArn;

                if(group.DBParameterGroupFamily && !group.DBParameterGroupFamily.startsWith('sqlserver')) return paramcb();

                if (group.DBParameterGroupName.startsWith('default.')) return paramcb();
                
                var parameters = helpers.addSource(cache, source,
                    ['rds', 'describeDBParameters', region, group.DBParameterGroupName]);
                
                if (!parameters) return paramcb();

                if (parameters.err || !parameters.data){
                    helpers.addResult(results, 3,
                        'Unable to query for parameters: ' + helpers.addError(parameters));
                    return paramcb();
                }

                if (!parameters.data.Parameters || !parameters.data.Parameters.length) {
                    helpers.addResult(results, 0, 'No parameters found');
                    return paramcb();
                }

                var tls10 = '';
                var tls11 = '';
                var tls12 = '';

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
                }

                if (tls10 === 'disabled' && tls11 === 'disabled' && tls12 === 'default') {
                    helpers.addResult(results, 0,
                        'DB parameter group ' + (group.DBParameterGroupName) + ' uses TLS 1.2',
                        region, resource);

                }
                else if (tls10 != 'disabled' || tls11 != 'disabled') {
                    helpers.addResult(results, 2,
                        'DB parameter group ' + (group.DBParameterGroupName) + ' does not use TLS 1.2',
                        region, resource);
                }

                paramcb();
            });
            
            rcb();
        
        }, function(){
            callback(null, results, source);
        });
    }
};
