var expect = require('chai').expect;
const openHadoopNameNodeWebUI = require('./openHadoopNameNodeWebUI');

const describeSecurityGroups = [
    {
        "Description": "System created security group.",
        "SecurityGroupName": "sg-rj998kwpxbxh3muao6nx",
        "VpcId": "vpc-rj9vu86hdve3qr173ew17",
        "ServiceManaged": false,
        "ResourceGroupId": "",
        "SecurityGroupId": "sg-rj998kwpxbxh3muao6nx",
        "CreationTime": "2021-04-30T09:57:23Z",
        "SecurityGroupType": "normal",
        "Tags": {
            "Tag": []
        }
    }
];

const describeSecurityGroupAttribute = [
    {
        "Description": "System created security group.",
        "RequestId": "B417712F-F2D9-4D84-9E14-53642866EC41",
        "SecurityGroupName": "sg-rj998kwpxbxh3muao6nx",
        "VpcId": "vpc-rj9vu86hdve3qr173ew17",
        "SecurityGroupId": "sg-rj998kwpxbxh3muao6nx",
        "Permissions": {
          "Permission": [
            {
                "Direction": "ingress",
                "SourceGroupName": "",
                "PortRange": "443/443",
                "SourceCidrIp": "0.0.0.0/0",
                "IpProtocol": "UDP"
            }
          ]
        }
    },
    {
        "Description": "System created security group.",
        "RequestId": "BCC3A7D9-93A5-44AA-85C1-A0C94A53DDBD",
        "SecurityGroupName": "sg-0xijcm5n3s67cgnlklmi",
        "VpcId": "vpc-0xitjib9awrnrv6i3sk9y",
        "SecurityGroupId": "sg-0xijcm5n3s67cgnlklmi",
        "Permissions": {
            "Permission": [
                {
                    "SourceGroupId": "",
                    "Policy": "Accept",
                    "Description": "System created rule.",
                    "SourcePortRange": "",
                    "Priority": 100,
                    "CreateTime": "2021-04-29T22:40:41Z",
                    "DestPrefixListName": "",
                    "Ipv6SourceCidrIp": "",
                    "NicType": "intranet",
                    "DestGroupId": "",
                    "Direction": "ingress",
                    "SourceGroupName": "",
                    "PortRange": "50070/50070",
                    "DestGroupOwnerAccount": "",
                    "DestPrefixListId": "",
                    "SourceCidrIp": "0.0.0.0/0",
                    "SourcePrefixListName": "",
                    "IpProtocol": "TCP",
                    "DestCidrIp": "",
                    "DestGroupName": "",
                    "SourceGroupOwnerAccount": "",
                    "Ipv6DestCidrIp": "",
                    "SourcePrefixListId": ""
                },
            ]
        }
    }
];

const createCache = (securityGroups, describeSecurityGroupAttribute, securityGroupsErr, describeSecurityGroupAttributeErr) => {
    const securityGroupId = (securityGroups && securityGroups.length) ? securityGroups[0].SecurityGroupId : null;
    return {
        ecs:{
            DescribeSecurityGroups: {
                'cn-hangzhou': {
                    err: securityGroupsErr,
                    data: securityGroups
                }
            },
            DescribeSecurityGroupAttribute: {
                'cn-hangzhou': {
                    [securityGroupId]: {
                        err: describeSecurityGroupAttributeErr,
                        data: describeSecurityGroupAttribute
                    }
                }
            }
        }
    };
};

describe('openHadoopNameNodeWebUI', function () {
    describe('run', function () {
        it('should PASS if no public open ports found', function (done) {
            const cache = createCache(describeSecurityGroups, describeSecurityGroupAttribute[0]);
            openHadoopNameNodeWebUI.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No public open ports found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should FAIL if security group has NameNodeWebUI TCP 50070 port open to public', function (done) {
            const cache = createCache(describeSecurityGroups, describeSecurityGroupAttribute[1]);
            openHadoopNameNodeWebUI.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has NameNodeWebUI:TCP:50070 open to 0.0.0.0/0');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no security groups found', function (done) {
            const cache = createCache([]);
            openHadoopNameNodeWebUI.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No security groups found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNWON unable to describe security groups', function (done) {
            const cache = createCache(null, { message: 'Unable to describe security groups'});
            openHadoopNameNodeWebUI.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to describe security groups');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    });
});
