var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Managed Instances',
    category: 'SSM',
    domain: 'Identity Access and Management',
    description: 'Ensure that all Amazon EC2 instances are managed by AWS Systems Manager (SSM).',
    more_info: 'Systems Manager simplifies AWS cloud resource management, quickly detects and resolve operational problems, and makes it easier to operate and manage your instances securely at large scale.',
    recommended_action: 'Configure AWS EC2 instance as SSM Managed Instances',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/managed_instances.html',
    apis: ['EC2:describeInstances', 'SSM:describeInstanceInformation', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ssm, function(region, rcb){
            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (!describeInstances.data || describeInstances.err) {
                helpers.addResult(results, 3, 'Unable to query for EC2 instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            }

            let ec2Instances = describeInstances.data.map((reservation) => reservation.Instances).flat();

            if (!ec2Instances.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            var describeInstanceInformation = helpers.addSource(cache, source,
                ['ssm', 'describeInstanceInformation', region]);

            if (!describeInstanceInformation || describeInstanceInformation.err || !describeInstanceInformation.data) {
                helpers.addResult(results, 3,
                    'Unable to query instance information: ' + helpers.addError(describeInstanceInformation), region);
                return rcb();
            }

            for (let ec2Instance of ec2Instances) {
                const arn = `arn:${awsOrGov}:ec2:${region}:${accountId}:instance/${ec2Instance.InstanceId}`;

                let instanceInfo = describeInstanceInformation.data.find((instanceInfo) => instanceInfo.InstanceId && instanceInfo.InstanceId === ec2Instance.InstanceId);

                if (instanceInfo) {
                    helpers.addResult(results, 0, `EC2 Instance: ${ec2Instance.InstanceId} is managed by AWS Systems Manager`, region, arn);
                } else {
                    helpers.addResult(results, 2, `EC2 Instance: ${ec2Instance.InstanceId} is not managed by AWS Systems Manager`, region, arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
