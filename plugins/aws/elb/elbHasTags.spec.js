const expect = require('chai').expect;
var elbHasTags = require('./elbHasTags');

const getResources = [
    {
        "ResourceARN": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/test-83",
        "Tags": [],
    },
     {
        "ResourceARN": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/test-83",
        "Tags": [{key: 'value'}],
    }
]

const describeLoadBalancers = [
    {
        "LoadBalancerName": "test-83",
        "DNSName": "test-83-1735080548.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneName": "test-83-1735080548.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneNameID": "Z35SXDOTRQ7X7K",
        "ListenerDescriptions": [
            {
                "Listener": {
                    "Protocol": "HTTP",
                    "LoadBalancerPort": 80,
                    "InstanceProtocol": "HTTP",
                    "InstancePort": 80
                },
                "PolicyNames": []
            }
        ],
        "Policies": {
            "AppCookieStickinessPolicies": [],
            "LBCookieStickinessPolicies": [],
            "OtherPolicies": []
        },
        "BackendServerDescriptions": [],
        "AvailabilityZones": [
            "us-east-1f",
            "us-east-1e",
            "us-east-1d",
            "us-east-1c",
            "us-east-1b",
            "us-east-1a"
        ],
        "Subnets": [
            "subnet-06aa0f60",
            "subnet-673a9a46",
            "subnet-6a8b635b",
            "subnet-aac6b3e7",
            "subnet-c21b84cc",
            "subnet-e83690b7"
        ],
        "VPCId": "vpc-99de2fe4",
        "Instances": [],
        "HealthCheck": {
            "Target": "HTTP:80/index.html",
            "Interval": 30,
            "Timeout": 5,
            "UnhealthyThreshold": 2,
            "HealthyThreshold": 10
        },
        "SourceSecurityGroup": {
            "OwnerAlias": "11112222333",
            "GroupName": "default"
        },
        "SecurityGroups": [
            "sg-aa941691"
        ],
        "CreatedTime": "2021-01-22T03:49:32.680000+00:00",
        "Scheme": "internet-facing"
    },
]

const createCache = (describeLoadBalancers, rgData) => {
    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: null,
                    data: describeLoadBalancers
                }
            },
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '111122223333'
                }
            }
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        },
    };
};

const createNullCache = () => {
    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': null
            }
        }
    };
};

describe('elbHasTags', function () {
    describe('run', function () {
       it('should PASS if classic load balancer have tags.', function (done) {
            const cache = createCache([describeLoadBalancers[0]], [getResources[1]]);
            elbHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ElasticLoadbalancing has tags');
                done();
            });
        });

        it('should FAIL if classic load balancer have no tags.', function (done) {
            const cache = createCache([describeLoadBalancers[0]], [getResources[0]]);
            elbHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ElasticLoadbalancing does not have any tags');
                done();
            });
        });

        it('should PASS if no load balancers found', function (done) {
            const cache = createCache([]);
            elbHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No load balancers found');
                done();
            });
        });

        it('should UNKNOWN if unable to describe load balancers', function (done) {
            const cache = createCache(null, { message: "Unable to describe load balancers" });
            elbHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for load balancers');
                done();
            });
        });

         it('should give unknown result if unable to query resource group tagging api', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources from group tagging api');
                done();
            };

            const cache = createCache(
                [describeLoadBalancers[0]],null);
            elbHasTags.run(cache, {}, callback);
         });
    });
});