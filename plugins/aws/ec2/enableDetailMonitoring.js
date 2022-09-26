
var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 Instances Detailed monitoring',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure that EC2 instances have enabled detailed monitoring.',
    more_info: 'By default, your instance is enabled for basic monitoring. You can optionally enable detailed monitoring. After you enable detailed monitoring, the Amazon EC2 console displays monitoring graphs with a 1-minute period for the instance.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html',
    recommended_action: 'Modify EC2 instance to enable detail monitoring',
    apis: ['EC2:describeInstances'],

    run: function(cache,settings,callback){
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2,function(region,rcb){
            var describeInstances = helpers.addSource(
                cache, source, ['ec2', 'describeInstances', region]);           
        
            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3, `Unable to query for instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No instances found', region);
                return rcb();
            }

            for (var reservation of describeInstances.data) {
                var accountId = reservation.OwnerId;
                for(var instance of reservation.Instances){
                    var arn = 'arn:aws:ec2:' + region + ':' + accountId + ':instance/' + instance.InstanceId;

                    if (!instance.Monitoring){
                        helpers.addResult(results, 3, 'Unable to get instance monitoring details', region, arn);
                        continue;
                    }else{

                        if(instance.Monitoring.State==='enabled'){
                            helpers.addResult(results, 0,
                                'Instance have detailed monitoring enabled', region, arn);
                        }else{
                        helpers.addResult(results, 2,
                            'Instance does not have detailed monitoring enabled', region, arn);
                        }
                    }
                }
                
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }

};