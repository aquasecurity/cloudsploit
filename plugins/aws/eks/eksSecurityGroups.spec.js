var expect = require('chai').expect;
var eks = require('./eksSecurityGroups');

const createCache = (listData, descSgData, descData) => {
    return {
        eks: {
            listClusters: {
                'us-east-1': {
                    err: null,
                    data: listData
                }
            },
            describeCluster: {
                'us-east-1': {
                    'mycluster': {
                        err: null,
                        data: descData
                    }
                }
            }
        },
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    data: descSgData
                }
            }
        }
    }
};

describe('eksSecurityGroups', function () {
    describe('run', function () {
        it('should give passing result if no EKS clusters present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No EKS clusters present')
                done()
            };

            const cache = createCache(
                [],
                {}
            );

            eks.run(cache, {}, callback);
        })

        it('should give error result if EKS control plane security groups allow additional access on unnecessary port ranges', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            };

            const cache = createCache(
                ['mycluster'],
                [
                    {
                        "Description": "eks sg",
                        "GroupName": "sg-1",
                        "IpPermissions": [
                            {
                                "FromPort": 22,
                                "IpProtocol": "tcp",
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0"
                                    }
                                ],
                                "Ipv6Ranges": [],
                                "PrefixListIds": [],
                                "ToPort": 22,
                                "UserIdGroupPairs": []
                            }
                        ],
                        "OwnerId": "111122223333",
                        "GroupId": "sg-02d95f133690f7400",
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
                ],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:111122223333:cluster/mycluster",
                    "resourcesVpcConfig": {
                        "subnetIds": [
                            "subnet-06aa0f60",
                            "subnet-673a9a46"
                        ],
                        "securityGroupIds": [
                            "sg-02d95f133690f7400"
                        ],
                        "vpcId": "vpc-99de2fe4",
                        "endpointPublicAccess": true,
                        "endpointPrivateAccess": false,
                        "publicAccessCidrs": [
                            "0.0.0.0/0"
                        ]
                    },
                  }
                }
            );

            eks.run(cache, {}, callback);
        })

        it('should give passing result if EKS control plane security groups do not contain unnecessary ports', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            };

            const cache = createCache(
                ['mycluster'],
                [
                    {
                        "Description": "eks sg",
                        "GroupName": "sg-1",
                        "IpPermissions": [
                            {
                                "FromPort": 443,
                                "IpProtocol": "tcp",
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0"
                                    }
                                ],
                                "Ipv6Ranges": [],
                                "PrefixListIds": [],
                                "ToPort": 443,
                                "UserIdGroupPairs": []
                            }
                        ],
                        "OwnerId": "111122223333",
                        "GroupId": "sg-02d95f133690f7400",
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
                ],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:111122223333:cluster/mycluster",
                    "resourcesVpcConfig": {
                        "subnetIds": [
                            "subnet-06aa0f60",
                            "subnet-673a9a46"
                        ],
                        "securityGroupIds": [
                            "sg-02d95f133690f7400"
                        ],
                        "vpcId": "vpc-99de2fe4",
                        "endpointPublicAccess": true,
                        "endpointPrivateAccess": false,
                        "publicAccessCidrs": [
                            "0.0.0.0/0"
                        ]
                    },
                  }
                }
            );

            eks.run(cache, {}, callback);
        })

        it('should give warn result if EKS control plane does not have security groups configured', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(1)
                done()
            };

            const cache = createCache(
                ['mycluster'],
                [
                    {
                        "Description": "eks sg",
                        "GroupName": "sg-1",
                        "IpPermissions": [
                            {
                                "FromPort": 443,
                                "IpProtocol": "tcp",
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0"
                                    }
                                ],
                                "Ipv6Ranges": [],
                                "PrefixListIds": [],
                                "ToPort": 443,
                                "UserIdGroupPairs": []
                            }
                        ],
                        "OwnerId": "111122223333",
                        "GroupId": "sg-02d95f133690f7400",
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
                ],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:111122223333:cluster/mycluster",
                  }
                }
            );

            eks.run(cache, {}, callback);
        })
    })
})