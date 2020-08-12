var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Transfer Logging Enabled',
    category: 'Transfer',
    description: 'Ensures AWS Transfer servers have CloudWatch logging enabled.',
    more_info: 'AWS Transfer servers can log activity to CloudWatch if a proper IAM service role is provided. This role should be configured for all servers to ensure proper access logging.',
    link: 'https://docs.aws.amazon.com/transfer/latest/userguide/monitoring.html',
    recommended_action: 'Provide a valid IAM service role for AWS Transfer servers.',
    apis: ['Transfer:listServers'],
    compliance: {
        hipaa: 'HIPAA requires that all data access is audited via proper logging configurations.',
        pci: 'PCI requires that all account access activity be logged.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.transfer, function(region, rcb){
            var listServers = helpers.addSource(cache, source,
                ['transfer', 'listServers', region]);

            if (!listServers) return rcb();

            if (listServers.err || !listServers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Transfer servers: ' + helpers.addError(listServers), region);
                return rcb();
            }

            if (!listServers.data.length) {
                helpers.addResult(results, 0, 'No Transfer servers found', region);
                return rcb();
            }

            for (var i in listServers.data) {
                var server = listServers.data[i];
                var arn = server.Arn;

                if (server.LoggingRole && server.LoggingRole.length) {
                    helpers.addResult(results, 0, 'Logging role is properly configured for Transfer server', region, arn);
                } else {
                    helpers.addResult(results, 2, 'Logging role is not configured for Transfer server', region, arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
