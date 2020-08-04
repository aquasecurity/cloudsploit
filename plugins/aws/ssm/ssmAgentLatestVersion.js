var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Agent Latest Version',
    category: 'SSM',
    description: 'Ensures SSM agents installed on Linux hosts are running the latest version',
    more_info: 'SSM agent software provides sensitive access to servers and should be kept up-to-date.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html',
    recommended_action: 'Update the SSM agent on all Linux hosts to the latest version.',
    apis: ['SSM:describeInstanceInformation', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ssm, function(region, rcb){
            var describeInstanceInformation = helpers.addSource(cache, source,
                ['ssm', 'describeInstanceInformation', region]);

            if (!describeInstanceInformation) return rcb();

            if (describeInstanceInformation.err || !describeInstanceInformation.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SSM instance information: ' + helpers.addError(describeInstanceInformation), region);
                return rcb();
            }

            if (!describeInstanceInformation.data.length) {
                helpers.addResult(results, 0, 'No SSM installations found', region);
                return rcb();
            }

            var instanceListPass = [];
            var instanceListFail = [];

            for (var i in describeInstanceInformation.data) {
                var info = describeInstanceInformation.data[i];
                // arn:${Partition}:ec2:${Region}:${Account}:instance/${InstanceId}
                var arn = 'arn:aws:ec2:' + region + ':' + accountId + ':instance/' + info.InstanceId;

                if (info.PlatformType && info.PlatformType == 'Linux' &&
                    info.PingStatus && info.PingStatus == 'Online') {
                    if (info.IsLatestVersion) {
                        instanceListPass.push(arn);
                    } else {
                        instanceListFail.push(arn);
                    }
                }
            }

            if (!instanceListPass.length && !instanceListFail.length) {
                helpers.addResult(results, 0, 'No SSM-managed online Linux systems found', region);
            } else if (instanceListFail.length + instanceListPass.length <= 20) {
                instanceListPass.forEach(function(arn){
                    helpers.addResult(results, 0, 'Instance SSM agent is up to date', region, arn);
                });

                instanceListFail.forEach(function(arn){
                    helpers.addResult(results, 2, 'Instance SSM agent is out of date', region, arn);
                });
            } else if (instanceListFail.length) {
                helpers.addResult(results, 2, 'There are ' + instanceListFail.length + ' instances with an out-of-date SSM agent and ' + instanceListPass.length + ' instances with an in-date SSM agent.', region);
            } else {
                helpers.addResult(results, 0, 'All ' + instanceListPass.length + ' instances have an in-date SSM agent.', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
