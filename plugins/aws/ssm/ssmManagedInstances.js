// TODO: MOVE TO EC2
var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Managed Instances',
    category: 'SSM',
    domain: 'Identity Access and Management',
    description: 'Ensure that all Amazon EC2 instances are managed by AWS Systems Manager (SSM)',
    more_info: 'Systems Manager simplifies AWS cloud resource management, shortens the time to detect and resolve operational problems, and makes it easy to operate and manage your instances securely at scale.',
    recommended_action: 'Configure AWS EC2 instance as managed instances',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html#sysman-paramstore-securestring',
    apis: ['EC2:describeInstances', 'SSM:describeInstanceInformation', 'STS:getCallerIdentity'],
    settings: {},

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ssm, function(region, rcb){
            // Look for EC2 instances
            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (!describeInstances.data || describeInstances.err) {
                helpers.addResult(results, 3, 'Unable to query for EC2 instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            } else if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            var describeInstanceInformation = helpers.addSource(cache, source,
                ['ssm', 'describeInstanceInformation', region]);

            if (!describeInstanceInformation) return rcb();

            if (describeInstanceInformation.err || !describeInstanceInformation.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SSM instance information: ' + helpers.addError(describeInstanceInformation), region);
                return rcb();
            } else if (!describeInstanceInformation.data.length) {
                helpers.addResult(results, 2, 'No EC2 instance is managed by AWS Systems Manager', region);
                return rcb();
            }

            let ec2Instances = describeInstances.data.map((reservation) => reservation.Instances).flat();

            if (!ec2Instances.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            for (let instanceInfo of describeInstanceInformation.data) {
                const arn = `arn:aws:ec2:${region}:${accountId}:instance/${instanceInfo.InstanceId}`;

                let ec2Instance = ec2Instances.find((ec2Instance) => ec2Instance.InstanceId === instanceInfo.InstanceId);

                if (ec2Instance) {
                    helpers.addResult(results, 0, `EC2 Instance: ${ec2Instance.InstanceId} is managed by AWS Systems Manager`, region, arn);
                } else {
                    helpers.addResult(results, 2, `EC2 Instance: ${arn} is not managed by AWS Systems Manager`, region, arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
