var async = require('async');
var helpers = require('../../helpers');

Array.prototype.equals = function (array, strict) {
    if (!array)
        return false;

    if (arguments.length == 1)
        strict = true;

    if (this.length != array.length)
        return false;

    for (var i = 0; i < this.length; i++) {
        if (this[i] instanceof Array && array[i] instanceof Array) {
            if (!this[i].equals(array[i], strict))
                return false;
        }
        else if (strict && this[i] != array[i]) {
            return false;
        }
        else if (!strict) {
            return this.sort().equals(array.sort(), true);
        }
    }
    return true;
};

module.exports = {
    title: 'Overlapping SecurityGroups',
    category: 'EC2',
    description: 'Determine if security group doesnt overlap with other',
    more_info: 'Security groups should be created on a per-service basis and avoid allowing all ports or protocols.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Remove all overlapping security groups.',
    apis: ['EC2:describeSecurityGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        async.each(helpers.regions.ec2, function(region, rcb){
            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups present', region);
                return rcb();
            }

            var found = false;
            var groups = describeSecurityGroups.data;

            // loop through each  group
            var array_open_hash_map = {};
            for (group of groups) {

                var resource = 'arn:aws:ec2:' + region + ':' +
                    group.OwnerId + ':security-group/' + group.GroupId;
                    //group.OwnerId + ':security-group/'
                // loop through group IpPermissions
                for (permission of group.IpPermissions){

                    // now check IpProtocol != -1  because defualt has no rule
                    if (permission.IpProtocol !== -1 && permission.IpRanges.length > 0){
                        // create a hash for comparing this will
                        // eliminate 2 extra loops
                        var strhash = permission.IpProtocol + '#' +
                            permission.IpRanges[0].CidrIp + '#' +
                            permission.FromPort + '#' +
                            permission.ToPort;

                        if (Object.keys(array_open_hash_map).includes(strhash)) {
                            found = true;
                            msg = group.GroupId + ' duplicated with ' + array_open_hash_map[strhash]
                            helpers.addResult(results, 1,
                                'Security group: ' + group.GroupId +
                                ' and ' + array_open_hash_map[strhash] +
                                'overlaps each other ', region, resource);
                        } else {
                            array_open_hash_map[strhash] = group.GroupId;
                        }

                    }
                }
            }
            if (!found) {
                helpers.addResult(results, 0, 'No Overlapping SecurityGroups found', region);
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
