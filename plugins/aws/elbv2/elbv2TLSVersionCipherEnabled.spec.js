var expect = require('chai').expect;
const elbv2TLSCipherEnabled = require('./elbv2TLSVersionCipherEnabled');

const loadBalancers = [
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/test-lb-43/8e680c7bace394a7",
        "DNSName": "test-lb-43-148538634.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2020-08-30T22:55:21.030Z",
        "LoadBalancerName": "test-lb-43",
        "Scheme": "internet-facing",
        "VpcId": "vpc-99de2fe4",
        "State": {
            "Code": "active"
        },
        "Type": "application",
        "AvailabilityZones": [
            {
                "ZoneName": "us-east-1c",
                "SubnetId": "subnet-aac6b3e7",
                "LoadBalancerAddresses": []
            },
            {
                "ZoneName": "us-east-1d",
                "SubnetId": "subnet-e83690b7",
                "LoadBalancerAddresses": []
            }
        ],
        "SecurityGroups": [
            "sg-06cccc47e5b3e1ee9"
        ],
        "IpAddressType": "ipv4"
    }
];

const loadBalancerAttributes = [
    {
        "Attributes": [
            {
                "Key": "access_logs.s3.enabled",
                "Value": "false"
            },
            {
                "Key": "access_logs.s3.bucket",
                "Value": ""
            },
            {
                "Key": "access_logs.s3.prefix",
                "Value": ""
            },
            {
                "Key": "idle_timeout.timeout_seconds",
                "Value": "60"
            },
            {
                "Key": "routing.http.x_amzn_tls_version_and_cipher_suite.enabled",
                "Value": "true"
            },
            {
                "Key": "routing.http2.enabled",
                "Value": "true"
            },
            {
                "Key": "routing.http.drop_invalid_header_fields.enabled",
                "Value": "false"
            },
            {
                "Key": "routing.http.desync_mitigation_mode",
                "Value": "defensive"
            }
        ]
    },
    {
        "Attributes": [
            {
                "Key": "access_logs.s3.enabled",
                "Value": "false"
            },
            {
                "Key": "access_logs.s3.bucket",
                "Value": ""
            },
            {
                "Key": "access_logs.s3.prefix",
                "Value": ""
            },
            {
                "Key": "idle_timeout.timeout_seconds",
                "Value": "60"
            },
            {
                "Key": "routing.http.x_amzn_tls_version_and_cipher_suite.enabled",
                "Value": "false"
            },
            {
                "Key": "routing.http2.enabled",
                "Value": "true"
            },
            {
                "Key": "routing.http.drop_invalid_header_fields.enabled",
                "Value": "false"
            },
            {
                "Key": "routing.http.desync_mitigation_mode",
                "Value": "defensive"
            }
        ]
    }
];

const createCache = (elbv2, attribute) => {
    let dnsName =elbv2.length > 0 ? elbv2[0].DNSName : '';
    return {
        elbv2:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elbv2
                },
            },
            describeLoadBalancerAttributes: {
                'us-east-1': {
                    [dnsName]: {
                        data: attribute
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: {
                        message: 'error describing classic load balancers'
                    },
                },
            },
            describeLoadBalancerAttributes: {
                'us-east-1': {
                    err: {
                        message: 'error describing application/network load balancers'
                    },
                },
            },
        }
    };
};

const createNullCache = () => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': null,
            },
            describeLoadBalancerAttributes: {
                'us-east-1': null,
            },
        },
    };
};

describe('elbv2TLSCipherEnabled', function () {
    describe('run', function () {
        it('should PASS if load balancer has TLS Version and Cipher Suite disabled', function (done) {
            const cache = createCache([loadBalancers[0]], loadBalancerAttributes[1]);
            elbv2TLSCipherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if load balancer has TLS Version and Cipher Suite enabled', function (done) {
            const cache = createCache([loadBalancers[0]], loadBalancerAttributes[0]);
            elbv2TLSCipherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        it('should PASS if no load balancer  found', function (done) {
            const cache = createCache([],[]);
            elbv2TLSCipherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Application/Network load balancers found');
                done();
            });
        });
        it('should FAIL if no load balancer attributes found', function (done) {
            const cache = createCache([loadBalancers[0]],[]);
            elbv2TLSCipherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Application/Network load balancer attributes not found');
                done();
            });
        });
        
        it('should UNKNOWN if error while describing load balancers', function (done) {
            const cache = createErrorCache();
            elbv2TLSCipherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Application/Network load balancers');
                done();
            });
        });
        
        it('should not return anything if unable to describe load balancers', function (done) {
            const cache = createNullCache();
            elbv2TLSCipherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
        
        
    });
});
