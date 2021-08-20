var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'PrivateLink in Use for Transfer for SFTP Server Endpoints',
    category: 'Transfer',
    description: 'Ensure that AWS Transfer for SFTP server endpoints are configured to use VPC endpoints powered by AWS PrivateLink.',
    more_info: 'PrivateLink provides secure and private connectivity between VPCs and other AWS resources using a dedicated network.',
    link: 'https://docs.aws.amazon.com/transfer/latest/userguide/update-endpoint-type-vpc.html',
    recommended_action: 'Configure the SFTP server endpoints to use endpoints powered by PrivateLink.',
    apis: ['Transfer:listServers'],

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

            listServers.data.forEach(server => {
                const isPrivate = (server.EndpointType && server.EndpointType != 'PUBLIC') ? true : false;
                helpers.addResult(results, isPrivate ? 0 : 2,
                    `Server '${server.ServerId}' is ${isPrivate ? '': 'not '}configured with private endpoint`, region, server.Arn);
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
