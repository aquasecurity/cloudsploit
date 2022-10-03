
const async = require('async');
const helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Instance Detailed Monitoring',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure that EC2 instances have detailed monitoring feature enabled.',
    more_info: 'By default, your instance is enabled for basic monitoring. After you enable detailed monitoring, EC2 console displays monitoring graphs with a 1-minute period.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html',
    recommended_action: 'Modify EC2 instance to enable detailed monitoring.',
    apis: ['EC2:describeInstances'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb) {
            const describeInstances = helpers.addSource(
                cache, source, ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3, `Unable to query for instances:
                   ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            for (const reservation of describeInstances.data) {
                const accountId = reservation.OwnerId;
                for (const instance of reservation.Instances) {
                    const arn = 'arn:aws:ec2:' + region + ':' + accountId + ':instance/' + instance.InstanceId;

                    if (instance.Monitoring && instance.Monitoring.State && instance.Monitoring.State.toLowerCase() === 'enabled') {
                        helpers.addResult(results, 0,
                            'Instance has enabled detailed monitoring', region, arn);
                    } else {
                        helpers.addResult(results, 2,
                            'Instance does not have enabled detailed monitoring', region, arn);
                    }
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },

};
