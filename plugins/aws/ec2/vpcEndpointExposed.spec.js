var expect = require('chai').expect;
const vpcEndpointExposed = require('./vpcEndpointExposed');

const vpcEndpoints = [
    {
        "VpcEndpointId": "vpce-004441c67cb8fb7f7",
        "VpcEndpointType": "Interface",
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
          "subnet-aac6b3e7"
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
    },
    {
        "VpcEndpointId": "vpce-004441c67cb8fb7f7",
        "VpcEndpointType": "Gateway",
        "VpcId": "vpc-99de2fe4",
        "ServiceName": "com.amazonaws.us-east-1.s3",
        "State": "available",
        "PolicyDocument": "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}",        
        "RouteTableIds": [],
        "SubnetIds": ["subnet-aac6b3e7"],
        "Groups": [],
        "PrivateDnsEnabled": false,
        "RequesterManaged": false,
        "NetworkInterfaceIds": [],
        "DnsEntries": [],
        "CreationTimestamp": "2020-10-23T05:24:02.000Z",
        "Tags": [],
        "OwnerId": "112233445566"
    },
];

const describeRouteTables = [
    {
        "Associations": [
          {
            "Main": true,
            "RouteTableAssociationId": "rtbassoc-79c7a000",
            "RouteTableId": "rtb-f6522690",
            "AssociationState": {
              "State": "associated"
            }
          }
        ],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-f6522690",
        "Routes": [
          {
            "DestinationCidrBlock": "172.31.0.0/16",
            "GatewayId": "local",
            "Origin": "CreateRouteTable",
            "State": "active"
          }
        ],
        "Tags": [],
        "VpcId": "vpc-0af5156c",
        "OwnerId": "000011112222"
    },
    {
        "Associations": [
          {
            "Main": true,
            "RouteTableAssociationId": "rtbassoc-79c7a000",
            "RouteTableId": "rtb-f6522690",
            "AssociationState": {
              "State": "associated"
            }
          }
        ],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-f6522690",
        "Routes": [
            {
                "DestinationCidrBlock": "172.31.0.0/16",
                "GatewayId": "local",
                "Origin": "CreateRouteTable",
                "State": "active"
            },
            {
                "DestinationCidrBlock": "172.31.0.0/16",
                "GatewayId": "igw-sedwednkq",
                "Origin": "CreateRouteTable",
                "State": "active"
            }
            
        ],
        "Tags": [],
        "VpcId": "vpc-0af515f7",
        "OwnerId": "000011112222"
    }
];

const describeSubnets = [
    {
        "AvailabilityZone": "us-east-1c",
        "AvailabilityZoneId": "use1-az4",
        "AvailableIpAddressCount": 4091,
        "CidrBlock": "172.31.16.0/20",
        "DefaultForAz": true,
        "MapPublicIpOnLaunch": true,
        "MapCustomerOwnedIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-aac6b3e7",
        "VpcId": "vpc-0af5156c",
        "OwnerId": "000011112222",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-1:000011112222:subnet/subnet-aac6b3e7"
    },
    {
        "AvailabilityZone": "us-east-1c",
        "AvailabilityZoneId": "use1-az4",
        "AvailableIpAddressCount": 4091,
        "CidrBlock": "172.31.16.0/20",
        "DefaultForAz": true,
        "MapPublicIpOnLaunch": true,
        "MapCustomerOwnedIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-aac6b3f7",
        "VpcId": "vpc-0af515f7",
        "OwnerId": "000011112222",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-1:000011112222:subnet/subnet-aac6b3e7"
    }
];

const createCache = (vpcEndpoints, subnets, routeTables) => {
    return {
        ec2: {
            describeVpcEndpoints: {
                'us-east-1': {
                    data: vpcEndpoints
                },
            },
            describeSubnets: {
                'us-east-1': {
                    data: subnets
                }
            },
            describeRouteTables: {
                'us-east-1': {
                    data: routeTables
                }
            }
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
            const cache = createCache([vpcEndpoints[0]], [describeSubnets[1]], [describeRouteTables[1]]);
            vpcEndpointExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if VPC endpoint is of Gateway type', function (done) {
            const cache = createCache([vpcEndpoints[2]], [describeSubnets[1]], [describeRouteTables[1]]);
            vpcEndpointExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if VPC endpoint is publicly exposed', function (done) {
            const cache = createCache([vpcEndpoints[1]], [describeSubnets[1]], [describeRouteTables[1]]);
            vpcEndpointExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if VPC endpoint is behind private subnet', function (done) {
            const cache = createCache([vpcEndpoints[1]], [describeSubnets[0]], [describeRouteTables[0]]);
            vpcEndpointExposed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
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
