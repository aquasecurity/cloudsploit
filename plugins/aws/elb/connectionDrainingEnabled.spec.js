const expect = require('chai').expect;
var connectionDrainingEnabled = require('./connectionDrainingEnabled');

const describeLoadBalancers = [
    {
        "LoadBalancerName": "akd-41",
        "DNSName": "akd-41-132269405.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneName": "akd-41-132269405.us-east-1.elb.amazonaws.com",
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
            "OwnerAlias": "111122223333",
            "GroupName": "default"
        },
        "SecurityGroups": [
            "sg-aa941691"
        ],
        "CreatedTime": "2021-01-24T04:40:45.520000+00:00",
        "Scheme": "internet-facing"
    }
];

const describeLoadBalancerAttributes = [
    {
        "LoadBalancerAttributes": {
            "CrossZoneLoadBalancing": {
                "Enabled": true
            },
            "AccessLog": {
                "Enabled": false
            },
            "ConnectionDraining": {
                "Enabled": true,
                "Timeout": 300
            },
            "ConnectionSettings": {
                "IdleTimeout": 60
            },
            "AdditionalAttributes": [
                {
                    "Key": "elb.http.desyncmitigationmode",
                    "Value": "defensive"
                }
            ]
        }
    },
    {
        "LoadBalancerAttributes": {
            "CrossZoneLoadBalancing": {
                "Enabled": true
            },
            "AccessLog": {
                "Enabled": false
            },
            "ConnectionDraining": {
                "Enabled": false,
                "Timeout": 300
            },
            "ConnectionSettings": {
                "IdleTimeout": 60
            },
            "AdditionalAttributes": [
                {
                    "Key": "elb.http.desyncmitigationmode",
                    "Value": "defensive"
                }
            ]
        }
    }
];



const createCache = (describeLoadBalancers, describeLoadBalancerAttributes, describeLoadBalancersErr, describeLoadBalancerAttributesErr) => {
    var dnsName = (describeLoadBalancers && describeLoadBalancers.length) ? describeLoadBalancers[0].DNSName : null;
    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: describeLoadBalancersErr,
                    data: describeLoadBalancers
                }
            },
            describeLoadBalancerAttributes: {
                'us-east-1': {
                    [dnsName]: {
                        err: describeLoadBalancerAttributesErr,
                        data: describeLoadBalancerAttributes
                    }
                }
            }
        }
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

describe('connectionDrainingEnabled', function () {
    describe('run', function () {
        it('should PASS if ELB has connection draining enabled', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeLoadBalancerAttributes[0], null, null);
            connectionDrainingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if ELB does not have connection draining enabled', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeLoadBalancerAttributes[1], null, null);
            connectionDrainingEnabled.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no load balancers found', function (done) {
            const cache = createCache([]);
            connectionDrainingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for load balancers', function (done) {
            const cache = createCache(null, null, { message: "Unable to describe load balancers" }, null);
            connectionDrainingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query load balancer attributes', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeLoadBalancerAttributes[1], null, { message: "Unable to describe load balancer attributes" });
            connectionDrainingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if describe load balancers response not found', function (done) {
            const cache = createNullCache();
            connectionDrainingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});