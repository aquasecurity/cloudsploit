var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SQL Server TLS Version',
    category: 'RDS',
    description: 'Ensures RDS SQL Servers do not allow outdated TLS certificate versions',
    more_info: 'TLS 1.2 or higher should be used for all TLS connections to RDS. A parameter group can be used to enforce this connection type.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2020/07/amazon-rds-for-sql-server-supports-disabling-old-versions-of-tls-and-ciphers/',
    recommended_action: 'Create a parameter group that contains the TLS version restriction and limit access to TLS 1.2 or higher',
    apis: ['RDS:describeDBParameterGroups', 'RDS: describeDBParameters'],
    
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

            async.each(describeDBParameterGroups.data, function(group, rcb){
                if (!group.DBParameterGroupName) return cb();
                
                console.log(group.DBParameterGroupName);
                var parameters = helpers.addSource(cache, source,
                    ['rds', 'describeDBParameters', region, group.DBParameterGroupName]);
                console.log(parameters);
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
