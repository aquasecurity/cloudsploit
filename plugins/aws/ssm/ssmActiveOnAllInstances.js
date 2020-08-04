var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Agent Active All Instances',
    category: 'SSM',
    description: 'Ensures SSM agents are installed and active on all servers',
    more_info: 'SSM allows for centralized monitoring of all servers and should be activated on all EC2 instances.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-setting-up.html',
    recommended_action: 'Install SSM on all servers and ensure it is active.',
    apis: ['EC2:describeInstances', 'SSM:describeInstanceInformation', 'STS:getCallerIdentity'],
    settings: {
        ssm_agent_threshold: {
            name: 'Threshold for EC2 SSM individual reporting.',
            description: 'Sets the value where EC2 instance reporting becomes aggregated once breached.',
            regex: '^[0-9]*$',
            default: 20
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var threshold = settings.ssm_agent_threshold || this.settings.ssm_agent_threshold.default;

        if (typeof threshold === 'string') {
            threshold.match(this.settings.ssm_agent_threshold.regex);
            threshold = parseInt(threshold);
        }

        async.each(regions.ssm, function(region, rcb){
            // Look for EC2 instances
            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);
            var describeInstanceInformation = helpers.addSource(cache, source,
                ['ssm', 'describeInstanceInformation', region]);

            if (!describeInstances || !describeInstanceInformation) return rcb();

            if (!describeInstances.data || describeInstances.err) {
                helpers.addResult(results, 3, 'Unable to query for EC2 instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            } else if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            if (describeInstanceInformation.err || !describeInstanceInformation.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SSM instance information: ' + helpers.addError(describeInstanceInformation), region);
                return rcb();
            }

            // Find number of instances
            var instanceList = [];
            describeInstances.data.forEach(function(reservation){
                reservation.Instances.forEach(function(instance){
                    instanceList.push(instance.InstanceId);
                });
            });

            if (!instanceList.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            var ssmMap = {};
            var instanceListPass = [];
            var instanceListFail = [];

            // Create map of instance ID -> SSM installation
            describeInstanceInformation.data.forEach(function(info){
                ssmMap[info.InstanceId] = info;
            });

            // See if every instance has SSM installed
            instanceList.forEach(function(id){
                var arn = 'arn:aws:ec2:' + region + ':' + accountId + ':instance/' + id;

                if (ssmMap[id] && ssmMap[id].PingStatus && ssmMap[id].PingStatus == 'Online') {
                    instanceListPass.push(arn);
                } else {
                    instanceListFail.push(arn);
                }
            });

            if (instanceListFail.length + instanceListPass.length <= threshold) {
                instanceListPass.forEach(function(arn){
                    helpers.addResult(results, 0, 'Instance has SSM agent installed and online', region, arn);
                });

                instanceListFail.forEach(function(arn){
                    helpers.addResult(results, 2, 'Instance does not have online SSM agent installed', region, arn);
                });
            } else if (instanceListFail.length) {
                helpers.addResult(results, 2, 'There are ' + instanceListFail.length + ' instances without online SSM agents installed and ' + instanceListPass.length + ' instances with online SSM agents installed.', region);
            } else {
                helpers.addResult(results, 0, 'All ' + instanceListPass.length + ' instances have an online SSM agent installed.', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
