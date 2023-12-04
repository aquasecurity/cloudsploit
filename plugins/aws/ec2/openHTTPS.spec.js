var expect = require('chai').expect;
const openHTTPS = require('./openHTTPS');

const describeSecurityGroups = [
    {
        "Description": "default VPC security group",
        "GroupName": "default",
        "IpPermissions": [],
        "OwnerId": "111122223333",
        "GroupId": "sg-aa941691",
        "IpPermissionsEgress": [],
        "VpcId": "vpc-99de2fe4"
    },
    {
        "Description": "Master group for Elastic MapReduce created on 2020-08-31T17:07:19.819Z",
        "GroupName": "ElasticMapReduce-master",
        "IpPermissions": [
            {
                "FromPort": 0,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 443,
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-02e2c70cd463dca29",
                        "UserId": "111122223333"
                    }
                ]
            },
            {
                "FromPort": 8443,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "72.21.196.64/29"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 8443,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-02e2c70cd463dca29",
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": []
            }
        ],
        "VpcId": "vpc-99de2fe4"
    },
    {
        "Description": "Master group for Elastic MapReduce created on 2020-08-31T17:07:19.819Z",
        "GroupName": "ElasticMapReduce-master",
        "IpPermissions": [
            {
                "FromPort": 0,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 65535,
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-02e2c70cd463dca29",
                        "UserId": "111122223333"
                    }
                ]
            },
            {
                "FromPort": 8443,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "72.21.196.64/29"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 8443,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-001639e564442dfec",
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": []
            }
        ],
        "VpcId": "vpc-99de2fe4"
    }
];

const describeNetworkInterfaces = [
    {
        "AvailabilityZone": "us-east-1b",
        "Description": "RDSNetworkInterface",
        "Groups": [
            {
                "GroupName": "default",
                "GroupId": "sg-aa941691"
            },
            {
                "GroupName": "HTTP-Access",
                "GroupId": "sg-02e2c70cd463dca29"
            },
        ],
        "InterfaceType": "interface",
        "Ipv6Addresses": [],
        "MacAddress": "12:95:7b:ae:63:91",
        "NetworkInterfaceId": "eni-0681cbf0930452492",
        "OwnerId": "111122223333",
        "PrivateDnsName": "ip-172-31-93-52.ec2.internal",
        "PrivateIpAddress": "172.31.93.52",
        "PrivateIpAddresses": [
            {
                "Primary": true,
                "PrivateDnsName": "ip-172-31-93-52.ec2.internal",
                "PrivateIpAddress": "172.31.93.52"
            }
        ],
        "Ipv4Prefixes": [],
        "Ipv6Prefixes": [],
        "RequesterId": "amazon-rds",
        "RequesterManaged": true,
        "SourceDestCheck": true,
        "Status": "available",
        "SubnetId": "subnet-673a9a46",
        "TagSet": [],
        "VpcId": "vpc-99de2fe4"
    },
]

const createCache = (securityGroups, networkInterfaces, functions, securityGroupsErr, networkInterfacesErr, functionsErr) => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': {
                    err: securityGroupsErr,
                    data: securityGroups
                }
            },
            describeNetworkInterfaces: {
                'us-east-1': {
                    err: networkInterfacesErr,
                    data: networkInterfaces
                }
            },
        },
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: functionsErr,
                    data: functions
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': null,
            },
            describeNetworkInterfaces: {
                'us-east-1': null,
            },
        },
        lambda: {
            listFunctions: {
                'us-east-1': null,
            },
        },
    };
};

describe('openHTTPS', function () {
    describe('run', function () {
        it('should PASS if no public open ports found', function (done) {
            const cache = createCache([describeSecurityGroups[0]], [describeNetworkInterfaces[0]]);
            openHTTPS.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if security group has HTTPS TCP port open to public', function (done) {
            const cache = createCache([describeSecurityGroups[1]], [describeNetworkInterfaces[0]]);
            openHTTPS.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no security groups found', function (done) {
            const cache = createCache([]);
            openHTTPS.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No security groups present')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNWON unable to describe security groups', function (done) {
            const cache = createCache(null, { message: 'Unable to describe security groups'});
            openHTTPS.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for security groups')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if describe security groups response not found', function (done) {
            const cache = createNullCache();
            openHTTPS.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should PASS if open port security group attached to the network interface has no public IP associated', function (done) {
            const cache = createCache([describeSecurityGroups[1]], [describeNetworkInterfaces[0]]);
            openHTTPS.run(cache, {check_network_interface:'true'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

    });
});

