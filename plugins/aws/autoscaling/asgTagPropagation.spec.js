var expect = require('chai').expect;
const asgTagPropagation = require('./asgTagPropagation');

const autoScalingGroups = [
    {
        "AutoScalingGroupName": "asg-all-tags-propagate",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/asg-all-tags-propagate",
        "MinSize": 1,
        "MaxSize": 3,
        "DesiredCapacity": 2,
        "DefaultCooldown": 300,
        "AvailabilityZones": [
            "us-east-1a",
            "us-east-1b"
        ],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
        "Instances": [],
        "CreatedTime": "2020-08-18T23:12:00.954Z",
        "Tags": [
            {
                "ResourceId": "asg-all-tags-propagate",
                "ResourceType": "auto-scaling-group",
                "Key": "Environment",
                "Value": "Production",
                "PropagateAtLaunch": true
            },
            {
                "ResourceId": "asg-all-tags-propagate",
                "ResourceType": "auto-scaling-group",
                "Key": "Owner",
                "Value": "DevOps",
                "PropagateAtLaunch": true
            }
        ],
        "TerminationPolicies": ["Default"]
    },
    {
        "AutoScalingGroupName": "asg-some-tags-propagate",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/asg-some-tags-propagate",
        "MinSize": 1,
        "MaxSize": 3,
        "DesiredCapacity": 2,
        "DefaultCooldown": 300,
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
        "Instances": [],
        "CreatedTime": "2020-08-18T23:12:00.954Z",
        "Tags": [
            {
                "ResourceId": "asg-some-tags-propagate",
                "ResourceType": "auto-scaling-group",
                "Key": "Environment",
                "Value": "Production",
                "PropagateAtLaunch": true
            },
            {
                "ResourceId": "asg-some-tags-propagate",
                "ResourceType": "auto-scaling-group",
                "Key": "Owner",
                "Value": "DevOps",
                "PropagateAtLaunch": false
            }
        ],
        "TerminationPolicies": ["Default"]
    },
    {
        "AutoScalingGroupName": "asg-no-tags",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/asg-no-tags",
        "MinSize": 1,
        "MaxSize": 3,
        "DesiredCapacity": 2,
        "DefaultCooldown": 300,
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
        "Instances": [],
        "CreatedTime": "2020-08-18T23:12:00.954Z",
        "Tags": [],
        "TerminationPolicies": ["Default"]
    },
    {
        "AutoScalingGroupName": "asg-no-tags-property",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/asg-no-tags-property",
        "MinSize": 1,
        "MaxSize": 3,
        "DesiredCapacity": 2,
        "DefaultCooldown": 300,
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
        "Instances": [],
        "CreatedTime": "2020-08-18T23:12:00.954Z",
        "TerminationPolicies": ["Default"]
    },
    {
        "AutoScalingGroupName": "asg-all-tags-not-propagate",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/asg-all-tags-not-propagate",
        "MinSize": 1,
        "MaxSize": 3,
        "DesiredCapacity": 2,
        "DefaultCooldown": 300,
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
        "Instances": [],
        "CreatedTime": "2020-08-18T23:12:00.954Z",
        "Tags": [
            {
                "ResourceId": "asg-all-tags-not-propagate",
                "ResourceType": "auto-scaling-group",
                "Key": "Environment",
                "Value": "Production",
                "PropagateAtLaunch": false
            },
            {
                "ResourceId": "asg-all-tags-not-propagate",
                "ResourceType": "auto-scaling-group",
                "Key": "Owner",
                "Value": "DevOps",
                "PropagateAtLaunch": false
            }
        ],
        "TerminationPolicies": ["Default"]
    }
];

const createCache = (asgs) => {
    return {
        autoscaling: {
            describeAutoScalingGroups: {
                'us-east-1': {
                    data: asgs
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        autoscaling: {
            describeAutoScalingGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing Auto Scaling groups'
                    },
                },
            },
        },
    };
};

describe('asgTagPropagation', function () {
    describe('run', function () {
        it('should PASS if all tags have PropagateAtLaunch set to true', function (done) {
            const cache = createCache([autoScalingGroups[0]]);
            asgTagPropagation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('all tags configured to propagate');
                done();
            });
        });

        it('should FAIL if some tags do not have PropagateAtLaunch set to true', function (done) {
            const cache = createCache([autoScalingGroups[1]]);
            asgTagPropagation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('1 tag(s) not configured to propagate');
                done();
            });
        });

        it('should PASS if Auto Scaling group has no tags', function (done) {
            const cache = createCache([autoScalingGroups[2]]);
            asgTagPropagation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has no tags configured');
                done();
            });
        });

        it('should PASS if Auto Scaling group has no Tags property', function (done) {
            const cache = createCache([autoScalingGroups[3]]);
            asgTagPropagation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has no tags configured');
                done();
            });
        });

        it('should FAIL if all tags have PropagateAtLaunch set to false', function (done) {
            const cache = createCache([autoScalingGroups[4]]);
            asgTagPropagation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('2 tag(s) not configured to propagate');
                done();
            });
        });

        it('should PASS if no Auto Scaling groups found', function (done) {
            const cache = createCache([]);
            asgTagPropagation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No auto scaling groups found');
                done();
            });
        });

        it('should UNKNOWN if error describing Auto Scaling groups', function (done) {
            const cache = createErrorCache();
            asgTagPropagation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query');
                done();
            });
        });
    });
});

