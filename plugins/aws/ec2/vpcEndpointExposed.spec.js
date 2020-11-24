var expect = require('chai').expect;
const vpcEndpointExposed = require('./vpcEndpointExposed');

const vpcEndpoints = [
    {
        "VpcEndpointId": "vpce-004441c67cb8fb7f7",
        "VpcEndpointType": "Gateway",
        "VpcId": "vpc-99de2fe4",
        "ServiceName": "com.amazonaws.us-east-1.s3",
        "State": "available",
        "PolicyDocument": "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}",        
        "RouteTableIds": [],
        "SubnetIds": [],
        "Groups": [],
        "PrivateDnsEnabled": false,
        "RequesterManaged": false,
        "NetworkInterfaceIds": [],
        "DnsEntries": [],
        "CreationTimestamp": "2020-10-23T05:24:02.000Z",
        "Tags": [],
        "OwnerId": "112233445566"
    },
    {
        "VpcEndpointId": "vpce-04f94cce3926725f1",
        "VpcEndpointType": "Interface",
        "VpcId": "vpc-99de2fe4",
        "ServiceName": "com.amazonaws.us-east-1.athena",
        "State": "available",
        "PolicyDocument": "{\n    \"Statement\": [\n        {\n            \"Action\": \"*\",\n            \"Effect\": \"Allow\",\n            \"Resource\": \"*\",\n            \"Principal\": \"*\"\n        }\n    ]\n}",
        "RouteTableIds": [],
        "SubnetIds": [
          "subnet-6a8b635b",
          "subnet-c21b84cc",
        ],
        "Groups": [
          {
            "GroupId": "sg-aa941691",
            "GroupName": "default"
          }
        ],
        "PrivateDnsEnabled": true,
        "RequesterManaged": false,
        "NetworkInterfaceIds": [
          "eni-0d830573a71f0adf3",
          "eni-091313ac29683c395",
        ],
        "CreationTimestamp": "2020-10-26T17:39:09.501Z",
        "Tags": [],
        "OwnerId": "112233445566"
    }
]

const createCache = (vpcEndpoints) => {
    return {
        ec2: {
            describeVpcEndpoints: {
                'us-east-1': {
                    data: vpcEndpoints
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeVpcEndpoints: {
                'us-east-1': {
                    err: {
                        message: 'error describing VPC endpoints'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeVpcEndpoints: {
                'us-east-1': null,
            },
        },
    };
};

describe('vpcEndpointExposed', function () {
    describe('run', function () {
        it('should PASS if VPC endpoint is not exposed', function (done) {
            const cache = createCache([vpcEndpoints[0]]);
            vpcEndpointExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if VPC endpoint is publicly exposed', function (done) {
            const cache = createCache([vpcEndpoints[1]]);
            vpcEndpointExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no VPC endpoints found', function (done) {
            const cache = createCache([]);
            vpcEndpointExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there unable to query for VPC endpoints', function (done) {
            const cache = createErrorCache();
            vpcEndpointExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results describe VPC endpoints response not found', function (done) {
            const cache = createNullCache();
            vpcEndpointExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
