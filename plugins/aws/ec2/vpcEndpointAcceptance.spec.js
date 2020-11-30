var expect = require('chai').expect;
const vpcEndpointAcceptance = require('./vpcEndpointAcceptance');

const vpcEndpointServices = [
    {
        "ServiceName": "com.amazonaws.vpce.us-east-1.vpce-svc-09d3a6a098dce6e8c",
        "ServiceId": "vpce-svc-09d3a6a098dce6e8c",
        "ServiceType": [
        {
            "ServiceType": "Interface"
        }
        ],
        "AvailabilityZones": [
        "us-east-1a",
        "us-east-1b"
        ],
        "Owner": "123456654321",
        "BaseEndpointDnsNames": [
        "vpce-svc-09d3a6a098dce6e8c.us-east-1.vpce.amazonaws.com"
        ],
        "VpcEndpointPolicySupported": false,
        "AcceptanceRequired": true,
        "ManagesVpcEndpoints": false,
        "Tags": []
    },
    {
        "ServiceName": "com.amazonaws.vpce.us-east-1.vpce-svc-09145867a106679a3",
        "ServiceId": "vpce-svc-09145867a106679a3",
        "ServiceType": [
          {
            "ServiceType": "Interface"
          }
        ],
        "AvailabilityZones": [
          "us-east-1a",
          "us-east-1b",
          "us-east-1c"
        ],
        "Owner": "123456654321",
        "BaseEndpointDnsNames": [
          "vpce-svc-09145867a106679a3.us-east-1.vpce.amazonaws.com"
        ],
        "VpcEndpointPolicySupported": false,
        "AcceptanceRequired": false,
        "ManagesVpcEndpoints": false,
        "Tags": []
    },
]

const createCache = (ServiceDetails) => {
    return {
        ec2: {
            describeVpcEndpointServices: {
                'us-east-1': {
                    data: ServiceDetails
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeVpcEndpointServices: {
                'us-east-1': {
                    err: {
                        message: 'error describing VPC endpoint services'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeVpcEndpointServices: {
                'us-east-1': null,
            },
        },
    };
};

describe('vpcEndpointAcceptance', function () {
    describe('run', function () {
        it('should PASS if VPC endpoint service requires acceptance by the service owner', function (done) {
            const cache = createCache([vpcEndpointServices[0]]);
            vpcEndpointAcceptance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if VPC endpoint service does not require acceptance by the service owner', function (done) {
            const cache = createCache([vpcEndpointServices[1]]);
            vpcEndpointAcceptance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no VPC endpoint service is detected', function (done) {
            const cache = createCache([]);
            vpcEndpointAcceptance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for VPC endpoint services', function (done) {
            const cache = createErrorCache();
            vpcEndpointAcceptance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for VPC endpoint services', function (done) {
            const cache = createNullCache();
            vpcEndpointAcceptance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
