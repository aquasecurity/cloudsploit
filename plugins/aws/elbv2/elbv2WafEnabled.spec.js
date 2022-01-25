var expect = require('chai').expect;
const elbv2WafEnabled = require('./elbv2WafEnabled');

const describeLoadBalancers = [
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:000111222333:loadbalancer/app/sad-elb/0c48be96f812e564",
        "DNSName": "sad-elb-2137190229.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2021-12-28T11:00:35.740Z",
        "LoadBalancerName": "sad-elb",
        "Scheme": "internet-facing",
        "VpcId": "vpc-0f4f4575a74fac014",
        "State": {
          "Code": "active"
        },
        "Type": "application",
        "AvailabilityZones": [
          {
            "ZoneName": "us-east-1a",
            "SubnetId": "subnet-02ed4181800d4658b",
            "LoadBalancerAddresses": []
          },
          {
            "ZoneName": "us-east-1b",
            "SubnetId": "subnet-06629b4200870c740",
            "LoadBalancerAddresses": []
          }
        ],
        "SecurityGroups": [
          "sg-0cb6c99daaa6b73c5"
        ],
        "IpAddressType": "ipv4"
    },
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:000111222333:loadbalancer/app/sad-elb2/c09ae5d45f51b7b3",
        "DNSName": "sad-elb2-1999742259.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2021-12-28T11:03:12.930Z",
        "LoadBalancerName": "sad-elb2",
        "Scheme": "internet-facing",
        "VpcId": "vpc-0f4f4575a74fac014",
        "State": {
          "Code": "active"
        },
        "Type": "application",
        "AvailabilityZones": [
          {
            "ZoneName": "us-east-1a",
            "SubnetId": "subnet-02ed4181800d4658b",
            "LoadBalancerAddresses": []
          },
          {
            "ZoneName": "us-east-1b",
            "SubnetId": "subnet-06629b4200870c740",
            "LoadBalancerAddresses": []
          }
        ],
        "SecurityGroups": [
          "sg-0cb6c99daaa6b73c5"
        ],
        "IpAddressType": "ipv4"
    }
];

const listWebACLs = [
    {
        "WebACLId": "5fde1d39-53e3-496b-ab3f-41d9aca7f4a7",
        "Name": "sad-acl"
    },
    {
        "WebACLId": "e0f3d7c9-9f75-4ace-b004-04e888a1372a",
        "Name": "sad-acl2"
    }
];

const listResourcesForWebACL = [
    {
        "ResourceArns": []
    },
    {
        "ResourceArns": [
          "arn:aws:elasticloadbalancing:us-east-1:000111222333:loadbalancer/app/sad-elb/0c48be96f812e564"      
        ]
    }
];


const createCache = (elbv2, WebACLs, webData) => {
    var webId = (WebACLs && WebACLs.length) ? WebACLs[0].WebACLId : null;

    return {
        elbv2:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elbv2
                },
            },
        },
        wafregional: {
            listWebACLs: {
                'us-east-1': {
                    data: WebACLs
                },
            },
            listResourcesForWebACL: {
                'us-east-1': {
                        [webId]: {
                            data: webData
                    },
                },
            }
        },
        wafv2: {
            listWebACLs: {
                'us-east-1': {
                    data: []
                },
            }
        }
    };
};

const createErrorCache = () => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: {
                        message: 'error describing Application/Application Load balancers'
                    },
                },
            },
        },
        wafregional: {
            listWebACLs: {
                'us-east-1': {
                    err: {
                        message: 'Error listing web ACLS'
                    }
                }
            },
            listResourcesForWebACL: {
                'us-east-1': {
                    err: {
                        message: 'Error listing resources for web ACLS'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': null,
            },
        },
        wafregional: {
            listWebACLs: {
                'us-east-1': null,
            },
            listResourcesForWebACL: {
                'us-east-1': null,
            }
        }
    };
};

describe('elbv2WafEnabled', function () {
    describe('run', function () {
        it('should PASS if Application Load Balancer has WAF enabled', function (done) {
            const cache = createCache([describeLoadBalancers[0]], [listWebACLs[1]], listResourcesForWebACL[1]);
            elbv2WafEnabled.run(cache, {}, (err, results) => {
                console.log(results);
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Application Load Balancer does not have WAF enabled', function (done) {
            const cache = createCache([describeLoadBalancers[1]], [listWebACLs[0]], listResourcesForWebACL[0]);
            elbv2WafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No Application Load Balancers found', function (done) {
            const cache = createCache([], []);
            elbv2WafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe Application Load Balancers', function (done) {
            const cache = createErrorCache();
            elbv2WafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe Load Balancers response is not found', function (done) {
            const cache = createNullCache();
            elbv2WafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});