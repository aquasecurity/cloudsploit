var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Overlapping Security Groups',
    category: 'EC2',
    description: 'Determine if EC2 instances have security groups that share the same rules',
    more_info: 'Overlapping security group rules make managing EC2 instance access much more difficult. ' +
               'If a rule is removed from one security group, the access may still remain in another, ' +
               'resulting in unintended access to the instance.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Structure security groups to provide a single category of access and do not ' +
                        'duplicate rules across groups used by the same instances.',
    apis: ['EC2:describeInstances', 'EC2:describeSecurityGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups found', region);
                return rcb();
            }

            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No instances found', region);
                return rcb();
            }

            // Convert group rules into a mapping of ID -> array of rules
            var sgMap = {};

            for (var s in describeSecurityGroups.data) {
                var sg = describeSecurityGroups.data[s];

                for (var p in sg.IpPermissions) {
                    var pm = sg.IpPermissions[p];

                    if (!pm.FromPort || !pm.ToPort || !pm.IpProtocol ||
                        !pm.IpRanges || !pm.Ipv6Ranges ||
                        !pm.UserIdGroupPairs) continue;

                    var sgArr = [];
                    var sgStr = [pm.IpProtocol, pm.FromPort, pm.ToPort].join(',');

                    for (var r in pm.IpRanges) {
                        sgArr.push(sgStr + ',' + pm.IpRanges[r].CidrIp);
                    }

                    for (var t in pm.Ipv6Ranges) {
                        sgArr.push(sgStr + ',' + pm.Ipv6Ranges[t].CidrIpv6);
                    }

                    for (var u in pm.UserIdGroupPairs) {
                        sgArr.push(sgStr + ',' + pm.UserIdGroupPairs[u].GroupId);
                    }

                    sgMap[sg.GroupId] = sgArr;
                }
            }

            var overlaps = {};

            for (var i in describeInstances.data) {
                var accountId = describeInstances.data[i].OwnerId;

                for (var j in describeInstances.data[i].Instances) {
                    var instance = describeInstances.data[i].Instances[j];
                    var instanceId = instance.InstanceId;
                    var instanceSgs = instance.SecurityGroups;

                    // Skip instances with only one SG
                    if (instanceSgs.length < 2) continue;

                    var ruleMap = {};
                    
                    for (var v in instanceSgs) {
                        var groupId = instanceSgs[v].GroupId;
                        if (!sgMap[groupId]) continue;

                        for (var w in sgMap[groupId]) {
                            var rule = sgMap[groupId][w];
                            if (ruleMap[rule]) {
                                var otherGroupId = ruleMap[rule];
                                // Rule already exists
                                // Ignore overlaps within same rule
                                if (groupId === otherGroupId) continue;

                                var ruleStr = ' (' + rule.replace(/,/g, ', ') + ')';

                                var compOp1 = groupId + '/' + otherGroupId + ruleStr;
                                var compOp2 = otherGroupId + '/' + groupId + ruleStr;

                                // arn:aws:ec2:region:account-id:instance/instance-id
                                var arn = 'arn:aws:ec2:' + region + ':' + accountId + ':instance/' + instanceId;

                                if (!overlaps[arn]) {
                                    overlaps[arn] = [compOp1];
                                } else {
                                    if (overlaps[arn].indexOf(compOp1) === -1 &&
                                        overlaps[arn].indexOf(compOp2) === -1) {
                                        overlaps[arn].push(compOp1);
                                    }
                                }
                            } else {
                                ruleMap[rule] = groupId;
                            }
                        }
                    }
                }
            }

            if (!Object.keys(overlaps).length) {
                helpers.addResult(results, 0, 'No overlapping instance security groups found', region);
            } else if (Object.keys(overlaps).length > 20) {
                helpers.addResult(results, 1, 'More than 20 EC2 instances have overlapping security groups', region);
            } else {
                for (var x in overlaps) {
                    helpers.addResult(results, 1,
                        'Instance has overlapping security group rules via groups: ' + overlaps[x].join(', '),
                        region, x);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};