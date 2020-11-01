var expect = require('chai').expect;
const elbHealthCheckActive = require('./elbHealthCheckActive');

const describeAutoScalingGroups = [
    {
        "AutoScalingGroupName": "test-38",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:112233445566:autoScalingGroup:724d79e1-0e79-43f2-a65e-52a60d4868f9:autoScalingGroupName/test-38",
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "LoadBalancerNames": [],
        "TargetGroupARNs": [],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
        "Instances": [
            {
                "InstanceId": "i-024af59c474e116ec",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1a",
                "LifecycleState": "InService",
                "HealthStatus": "Healthy",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-0f1f6b356026abc86",
                    "LaunchTemplateName": "auto-scaling-template",
                    "Version": "1"
                },
                "ProtectedFromScaleIn": false
            }
        ]
    },
    {
        "AutoScalingGroupName": "test-38",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:112233445566:autoScalingGroup:724d79e1-0e79-43f2-a65e-52a60d4868f9:autoScalingGroupName/test-38",
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "LoadBalancerNames": [
            "test-38-classic"
        ],
        "TargetGroupARNs": [
            "arn:aws:elasticloadbalancing:us-east-1:112233445566:targetgroup/temp-tg/fee5b45af37af625"
        ],
        "HealthCheckType": "ELB",
        "HealthCheckGracePeriod": 300,
        "Instances": [
            {
                "InstanceId": "i-024af59c474e116ec",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1a",
                "LifecycleState": "InService",
                "HealthStatus": "Healthy",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-0f1f6b356026abc86",
                    "LaunchTemplateName": "auto-scaling-template",
                    "Version": "1"
                },
                "ProtectedFromScaleIn": false
            }
        ]
    },
    {
        "AutoScalingGroupName": "test-38",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:112233445566:autoScalingGroup:724d79e1-0e79-43f2-a65e-52a60d4868f9:autoScalingGroupName/test-38",
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "LoadBalancerNames": [],
        "TargetGroupARNs": [
            "arn:aws:elasticloadbalancing:us-east-1:112233445566:targetgroup/temp-tg/fee5b45af37af625"
        ],
        "HealthCheckType": "ELB",
        "HealthCheckGracePeriod": 300,
        "Instances": [
            {
                "InstanceId": "i-024af59c474e116ec",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1a",
                "LifecycleState": "InService",
                "HealthStatus": "Healthy",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-0f1f6b356026abc86",
                    "LaunchTemplateName": "auto-scaling-template",
                    "Version": "1"
                },
                "ProtectedFromScaleIn": false
            }
        ]
    },
    {
        "AutoScalingGroupName": "test-38-2",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:112233445566:autoScalingGroup:724d79e1-0e79-43f2-a65e-52a60d4868f9:autoScalingGroupName/test-38-2",
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "LoadBalancerNames": [
            "test-38-classic",
        ],
        "TargetGroupARNs": [],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
        "Instances": [
            {
                "InstanceId": "i-024af59c474e116ec",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1a",
                "LifecycleState": "InService",
                "HealthStatus": "Healthy",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-0f1f6b356026abc86",
                    "LaunchTemplateName": "auto-scaling-template",
                    "Version": "1"
                },
                "ProtectedFromScaleIn": false
            }
        ]
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

const createNullCache = () => {
    return {
        autoscaling: {
            describeAutoScalingGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('elbHealthCheckActive', function () {
    describe('run', function () {
        it('should PASS if Auto Scaling group does not use ELBs', function (done) {
            const cache = createCache([describeAutoScalingGroups[2]]);
            elbHealthCheckActive.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if Auto Scaling group has ELB health check active', function (done) {
            const cache = createCache([describeAutoScalingGroups[1]]);
            elbHealthCheckActive.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if Auto Scaling group does not use ELBs', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]]);
            elbHealthCheckActive.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Auto Scaling group does not have ELB health check active', function (done) {
            const cache = createCache([describeAutoScalingGroups[3]]);
            elbHealthCheckActive.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Auto Scaling groups found', function (done) {
            const cache = createCache([]);
            elbHealthCheckActive.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe Auto Scaling groups', function (done) {
            const cache = createErrorCache();
            elbHealthCheckActive.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if no response found for describe Auto Scaling groups', function (done) {
            const cache = createNullCache();
            elbHealthCheckActive.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});